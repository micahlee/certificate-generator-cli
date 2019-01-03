package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/micahlee/certificate-generator-cli/lib"
	"github.com/spf13/cobra"
)

var cfgFile = ""

var rootCmd = &cobra.Command{
	Use:   "cert-gen",
	Short: "Simple PKI certificate generator",
	Long:  `A Fast and Flexible PKI certificate generator for complex PKI architectures.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		if cfgFile == "" {
			return errors.New("Config file name is not valid")
		}

		config, err := lib.LoadConfiguration(cfgFile)
		if err != nil {
			return err
		}

		if err := lib.GenerateCertificates(config); err != nil {
			return err
		}

		// No errors
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "certificates.yml", "certificate configuration file")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
