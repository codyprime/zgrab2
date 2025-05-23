package ssh

import (
	"errors"
	"fmt"
	"strings"
)

func MakeSSHConfig() *ClientConfig {
	ret := new(ClientConfig)
	ret.HostKeyAlgorithms = supportedHostKeyAlgos
	ret.KeyExchanges = supportedKexAlgos
	ret.Ciphers = supportedCiphers
	return ret
}

func (c *ClientConfig) SetHostKeyAlgorithms(value string) error {
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range supportedHostKeyAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`host key algorithm not supported: "%s"`, alg))
		}

		c.HostKeyAlgorithms = append(c.HostKeyAlgorithms, alg)
	}
	return nil
}

func (c *ClientConfig) SetKexAlgorithms(value string) error {
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range supportedKexAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`DH KEX algorithm not supported: "%s"`, alg))
		}

		c.KeyExchanges = append(c.KeyExchanges, alg)
	}
	return nil
}

func (c *ClientConfig) SetCiphers(value string) error {
	for _, inCipher := range strings.Split(value, ",") {
		isValid := false
		for _, knownCipher := range supportedCiphers {
			if inCipher == knownCipher {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`cipher not supported: "%s"`, inCipher))
		}

		c.Ciphers = append(c.Ciphers, inCipher)
	}

	return nil
}
