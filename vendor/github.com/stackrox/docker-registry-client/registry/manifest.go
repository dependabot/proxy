package registry

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/ocischema"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/opencontainers/go-digest"
)

// Opt to define these constants here instead of importing
// github.com/opencontainers/image-spec/specs-go/v1
// to ensure we use the docker/distribution library for unmarshalling purposes.
const (
	// MediaTypeImageManifest specifies the media type for an image manifest.
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"
	// MediaTypeImageIndex specifies the media type for an image index.
	MediaTypeImageIndex = "application/vnd.oci.image.index.v1+json"
)

func (registry *Registry) Manifest(repository, reference string) (*schema1.SignedManifest, error) {
	return registry.v1Manifest(repository, reference, schema1.MediaTypeManifest)
}

func (registry *Registry) SignedManifest(repository, reference string) (*schema1.SignedManifest, error) {
	return registry.v1Manifest(repository, reference, schema1.MediaTypeSignedManifest)
}

func (registry *Registry) ManifestList(repository, reference string) (*manifestlist.DeserializedManifestList, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.get url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", manifestlist.MediaTypeManifestList)
	resp, err := registry.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	deserialized := &manifestlist.DeserializedManifestList{}
	err = deserialized.UnmarshalJSON(body)
	if err != nil {
		return nil, err
	}
	return deserialized, nil
}

func (registry *Registry) v1Manifest(repository, reference string, mediaType string) (*schema1.SignedManifest, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.get url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", mediaType)
	resp, err := registry.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	signedManifest := &schema1.SignedManifest{}
	err = signedManifest.UnmarshalJSON(body)
	if err != nil {
		return nil, err
	}

	return signedManifest, nil
}

func (registry *Registry) ManifestV2(repository, reference string) (*schema2.DeserializedManifest, error) {
	deserialized, _, err := registry.ManifestV2WithDigest(repository, reference)
	return deserialized, err
}

// ManifestV2WithDigest extends ManifestV2 to return the digest found in the Docker-Content-Digest header.
// If the header does not exist or is invalid an empty digest is returned (an error is not returned
// so that existing clients are not affected by new, potentially unrelated, errors).
func (registry *Registry) ManifestV2WithDigest(repository, reference string) (*schema2.DeserializedManifest, digest.Digest, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.get url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Accept", schema2.MediaTypeManifest)
	resp, err := registry.Client.Do(req)
	if err != nil {
		return nil, "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	deserialized := &schema2.DeserializedManifest{}
	err = deserialized.UnmarshalJSON(body)
	if err != nil {
		return nil, "", err
	}

	digest, err := digest.Parse(resp.Header.Get("Docker-Content-Digest"))
	if err != nil {
		digest = ""
	}
	return deserialized, digest, nil
}

func (registry *Registry) ImageIndex(repository, reference string) (*manifestlist.DeserializedManifestList, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.get url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", MediaTypeImageIndex)
	resp, err := registry.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	deserialized := &manifestlist.DeserializedManifestList{}
	err = deserialized.UnmarshalJSON(body)
	if err != nil {
		return nil, err
	}
	return deserialized, nil
}

func (registry *Registry) ManifestOCI(repository, reference string) (*ocischema.DeserializedManifest, error) {
	deserialized, _, err := registry.ManifestOCIWithDigest(repository, reference)
	return deserialized, err
}

// ManifestOCIWithDigest extends ManifestOCI to return the digest found in the Docker-Content-Digest header.
// If the header does not exist or is invalid an empty digest is returned (an error is not returned
// so that existing clients are not affected by new, potentially unrelated, errors).
func (registry *Registry) ManifestOCIWithDigest(repository, reference string) (*ocischema.DeserializedManifest, digest.Digest, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.get url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Accept", MediaTypeImageManifest)
	resp, err := registry.Client.Do(req)
	if err != nil {
		return nil, "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	deserialized := &ocischema.DeserializedManifest{}
	err = deserialized.UnmarshalJSON(body)
	if err != nil {
		return nil, "", err
	}

	digest, err := digest.Parse(resp.Header.Get("Docker-Content-Digest"))
	if err != nil {
		digest = ""
	}

	return deserialized, digest, nil
}

func (registry *Registry) ManifestDigest(repository, reference string) (digest.Digest, string, error) {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.head url=%s repository=%s reference=%s", url, repository, reference)

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Add("Accept", schema2.MediaTypeManifest)
	req.Header.Add("Accept", schema1.MediaTypeManifest)
	req.Header.Add("Accept", schema1.MediaTypeSignedManifest)
	req.Header.Add("Accept", manifestlist.MediaTypeManifestList)
	req.Header.Add("Accept", MediaTypeImageManifest)
	req.Header.Add("Accept", MediaTypeImageIndex)

	resp, err := registry.Client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return "", "", err
	}

	contentType := resp.Header.Get("Content-Type")
	d, err := digest.Parse(resp.Header.Get("Docker-Content-Digest"))
	return d, contentType, err
}

func (registry *Registry) DeleteManifest(repository string, digest digest.Digest) error {
	if err := digest.Validate(); err != nil {
		return fmt.Errorf("invalid layer digest %v: %w", digest, err)
	}

	url := registry.url("/v2/%s/manifests/%s", repository, digest)
	registry.Logf("registry.manifest.delete url=%s repository=%s reference=%s", url, repository, digest)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	resp, err := registry.Client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return err
	}
	return nil
}

func (registry *Registry) PutManifest(repository, reference string, manifest distribution.Manifest) error {
	url := registry.url("/v2/%s/manifests/%s", repository, reference)
	registry.Logf("registry.manifest.put url=%s repository=%s reference=%s", url, repository, reference)

	mediaType, payload, err := manifest.Payload()
	if err != nil {
		return err
	}

	buffer := bytes.NewBuffer(payload)
	req, err := http.NewRequest("PUT", url, buffer)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", mediaType)
	resp, err := registry.Client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return err
}
