package main

import (
	"fmt"

	"github.com/fedi-e2ee/pkd-server-go/internal/auth"
	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.AddCommand(tokenMintCmd)
	tokenMintCmd.Flags().String("config", "", "config file (default is ./config.yaml)")
	tokenMintCmd.Flags().String("key-file", "pkd-server.key", "path to the key file")
	tokenMintCmd.Flags().String("password", "", "password for the key file")
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage authentication tokens",
}

var tokenMintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a new token pair",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}

		keyFile, _ := cmd.Flags().GetString("key-file")
		password, _ := cmd.Flags().GetString("password")

		repo, err := db.NewPostgresRepository(cmd.Context(), cfg.Database.DSN)
		if err != nil {
			return err
		}
		defer func() {
			if err := repo.Close(); err != nil {
				fmt.Printf("Error closing repository: %v\n", err)
			}
		}()

		keyManager, err := auth.NewFileKeyManager(
			keyFile,
			[]byte(password),
			cfg.Server.KeyFile.Argon2idTime,
			cfg.Server.KeyFile.Argon2idMemory,
			cfg.Server.KeyFile.Argon2idThreads,
		)
		if err != nil {
			return err
		}
		tokenService := auth.NewPasetoTokenService(keyManager, cfg, repo.DB())

		accessToken, refreshToken, err := tokenService.NewPair()
		if err != nil {
			return err
		}

		fmt.Println("Access Token:", accessToken)
		fmt.Println("Refresh Token:", refreshToken)

		return nil
	},
}
