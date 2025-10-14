package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	configFile string
	force      bool
)

func init() {
	generateKeysCmd.Flags().StringVar(&configFile, "config", "config.yaml", "path to the configuration file")
	generateKeysCmd.Flags().BoolVar(&force, "force", false, "overwrite existing keys")
	rootCmd.AddCommand(generateKeysCmd)
}

var generateKeysCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate Ed25519 and HPKE keys for the server",
	Long:  `Generates a new Ed25519 keypair for signing and an HPKE secret key for encryption.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Use viper to read the config file
		viper.SetConfigFile(configFile)
		// Attempt to read the config file, but ignore errors if it doesn't exist yet.
		_ = viper.ReadInConfig()

		// Check for existing keys
		privKeyExists := viper.GetString("server.private_key") != ""
		hpkeKeyExists := viper.GetString("server.hpke_secret_key") != ""

		if (privKeyExists || hpkeKeyExists) && !force {
			fmt.Fprintf(os.Stderr, "Error: keys already exist in %s. Use --force to overwrite.\n", configFile)
			os.Exit(1)
		}

		// Generate Ed25519 keypair
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println("Error generating Ed25519 key:", err)
			return
		}

		// Generate HPKE secret key
		hpkeSecretKey := make([]byte, 32)
		if _, err := rand.Read(hpkeSecretKey); err != nil {
			fmt.Println("Error generating HPKE secret key:", err)
			return
		}

		// Set the new keys in viper
		viper.Set("server.private_key", crypto.EncodePrivateKey(privKey))
		viper.Set("server.hpke_secret_key", base64.RawURLEncoding.EncodeToString(hpkeSecretKey))

		// Write the config file
		if err := viper.WriteConfig(); err != nil {
			// If the file doesn't exist, try to write it to the specified path
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				if err := viper.WriteConfigAs(configFile); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
					os.Exit(1)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Printf("Successfully generated and wrote keys to %s\n", configFile)
	},
}
