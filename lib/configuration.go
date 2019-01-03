package lib

import (
	"fmt"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"
)

type Certificate struct {
	CommonName       string `yaml:"common_name"`
	Country          string
	State            string
	Locality         string
	Organization     string
	OrganizationUnit string `yaml:"organization_unit"`
	Expires          string
	SubjectAltNames  []string `yaml:"subject_alternative_names"`

	InstallTo      string `yaml:"install_to"`
	FilenamePrefix string `yaml:"filename_prefix"`

	Issue []Certificate
}

// Note: struct fields must be public in order for unmarshal to
// correctly populate the data.
type Configuration struct {
	Certificates []Certificate
}

func LoadConfiguration(filename string) (Configuration, error) {
	config := Configuration{}

	if _, err := os.Stat(filename); err != nil {
		return config, err
	}

	fmt.Printf("Reading configuration from %v\n", filename)

	// Read configuration file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal([]byte(data), &config); err != nil {
		return config, err
	}

	return config, nil
}
