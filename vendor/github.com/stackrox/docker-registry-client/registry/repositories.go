package registry

import "strings"

type repositoriesResponse struct {
	Repositories []string `json:"repositories"`
}

func (registry *Registry) Repositories() ([]string, error) {
	url := registry.url("/v2/_catalog")
	repos := make([]string, 0, 10)
	var err error //We create this here, otherwise url will be rescoped with :=
	var response repositoriesResponse
	for {
		registry.Logf("registry.repositories url=%s", url)
		url, err = registry.getPaginatedJson(url, &response)
		// Sometimes only the path is returned instead of the full URL.
		// If that's the case, then prepend the scheme and host to the path.
		if strings.HasPrefix(url, "/") {
			// Do not use registry.url(), as there may be a % which will not work well with
			// fmt.Sprintf.
			// Instead, just use regular string concatenation.
			url = registry.URL + url
		}
		switch err {
		case ErrNoMorePages:
			repos = append(repos, response.Repositories...)
			return repos, nil
		case nil:
			repos = append(repos, response.Repositories...)
			continue
		default:
			return nil, err
		}
	}
}
