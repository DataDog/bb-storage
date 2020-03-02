package util

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	pb "github.com/buildbarn/bb-storage/pkg/proto/configuration/tls"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewTLSConfigFromClientConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS client. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromClientConfiguration(configuration *pb.TLSClientConfiguration) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	var tlsConfig tls.Config
	if configuration.ClientCertificate != "" && configuration.ClientPrivateKey != "" {
		// Serve a client certificate when provided.
		cert, err := tls.X509KeyPair([]byte(configuration.ClientCertificate), []byte(configuration.ClientPrivateKey))
		if err != nil {
			return nil, StatusWrap(err, "Failed to load X509 key pair")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if serverCAs := configuration.ServerCertificateAuthorities; serverCAs != "" {
		// Don't use the default root CA list. Use the ones
		// provided in the configuration instead.
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(serverCAs)) {
			return nil, status.Error(codes.InvalidArgument, "Failed to parse server certificate authorities")
		}
		tlsConfig.RootCAs = pool
	}

	return &tlsConfig, nil
}

// NewTLSConfigFromServerConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS server. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromServerConfiguration(configuration *pb.TLSServerConfiguration) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	tlsConfig := tls.Config{
		ClientAuth: tls.RequestClientCert,
	}

	switch backend := configuration.Backend.(type) {
	case *pb.TLSServerConfiguration_Static:
		// Require the use of server-side certificates.
		cert, err := tls.X509KeyPair([]byte(backend.Static.ServerCertificate), []byte(backend.Static.ServerPrivateKey))
		if err != nil {
			return nil, StatusWrap(err, "Failed to load X509 key pair")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		break
	case *pb.TLSServerConfiguration_Rotated:
		switch issuerBackend := backend.Rotated.Issuer.(type) {
		case *pb.RotatedTLSServerConfiguration_Filesystem:
			dur, err := ptypes.Duration(issuerBackend.Filesystem.RefreshInterval)
			if err != nil {
				return nil, errors.New("Duration is invalid")
			}

			tlsConfig.GetCertificate = newFilesystemGetCertificateFunc(issuerBackend.Filesystem.ServerCertificatePath, issuerBackend.Filesystem.ServerPrivateKeyPath, dur)
			break
		default:
			return nil, errors.New("Configuration did not contain a TLS certificate rotation issuer backend")
		}

		break
	default:
		return nil, errors.New("Configuration did not contain a TLS server backend") //TODO(griffin)
	}

	return &tlsConfig, nil
}

func newFilesystemGetCertificateFunc(tlsCertFile, tlsKeyFile string, refreshTime time.Duration) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		err            error
		cert           tls.Certificate
		certCreateTime time.Time
		muCert         sync.Mutex
	)

	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		muCert.Lock()
		defer muCert.Unlock()
		if time.Since(certCreateTime) < refreshTime {
			return &cert, nil
		}
		cert, err = tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			return nil, err
		}
		certCreateTime = time.Now()
		return &cert, nil
	}
}
