package main

import (
	"crypto/tls"
	"sync"
)

type certStore struct {
	certs map[string]*tls.Certificate
	sync.Mutex
}

func newCertStore() *certStore {
	return &certStore{
		certs: map[string]*tls.Certificate{},
	}
}

func (s *certStore) Fetch(host string, genCert func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.Lock()
	defer s.Unlock()

	cert, ok := s.certs[host]
	var err error
	if !ok {
		cert, err = genCert()
		if err != nil {
			return nil, err
		}
		s.certs[host] = cert
	}
	return cert, nil
}
