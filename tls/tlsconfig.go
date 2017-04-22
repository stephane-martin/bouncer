package tls


import "crypto/tls"
import "crypto/x509"
import "io/ioutil"
import "errors"
import "fmt"


// GetTLSConfig gets a tls.Config object from the given certs, key, and CA files.
// you must give the full path to the files.
// If all files are blank and InsecureSkipVerify=false, returns a nil pointer.
// shamelessly copied from telegraf (https://github.com/influxdata/telegraf/blob/master/internal/internal.go)
func GetTLSConfig(SSLCert, SSLKey, SSLCA string, InsecureSkipVerify bool) (*tls.Config, error) {
	if SSLCert == "" && SSLKey == "" && SSLCA == "" && !InsecureSkipVerify {
		return nil, nil
	}

	t := &tls.Config{
		InsecureSkipVerify: InsecureSkipVerify,
	}

	if SSLCA != "" {
		caCert, err := ioutil.ReadFile(SSLCA)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Could not load TLS CA: %s", err))
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		t.RootCAs = caCertPool
	}

	if SSLCert != "" && SSLKey != "" {
		cert, err := tls.LoadX509KeyPair(SSLCert, SSLKey)
		if err != nil {
			return nil, errors.New(fmt.Sprintf(
				"Could not load TLS client key/certificate from %s:%s: %s",
				SSLKey, SSLCert, err))
		}

		t.Certificates = []tls.Certificate{cert}
		t.BuildNameToCertificate()
	}

	// will be nil by default if nothing is provided
	return t, nil
}


