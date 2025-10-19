package main

import (
	"context"
	"fmt"

	"github.com/fedi-e2ee/pkd-server-go/internal/db"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(actorCmd)
	actorCmd.AddCommand(actorCryptoShredCmd)
	actorCryptoShredCmd.Flags().String("config", "", "config file (default is ./config.yaml)")
}

var actorCmd = &cobra.Command{
	Use:   "actor",
	Short: "Manage actors",
}

var actorCryptoShredCmd = &cobra.Command{
	Use:   "crypto-shred [actor-id]",
	Short: "Crypto-shred an actor's data",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		actorID := args[0]
		fmt.Printf("Crypto-shredding actor %s...\n", actorID)

		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}

		var repo db.Repository
		switch cfg.Database.Driver {
		case "sqlite":
			repo, err = db.NewSQLiteRepository(cmd.Context(), cfg.Database.DSN)
		case "postgres", "":
			repo, err = db.NewPostgresRepository(cmd.Context(), cfg.Database.DSN)
		default:
			return fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
		}
		if err != nil {
			return err
		}
		defer func() {
			if err := repo.Close(); err != nil {
				fmt.Printf("Error closing repository: %v\n", err)
			}
		}()

		service := domain.NewPKDService(repo, nil)
		// For now, we just erase everything upon request.
		//
		// In the future, more granular erasure may be desirable.
		err = service.CryptoShred(context.Background(), actorID)
		if err != nil {
			return err
		}

		fmt.Println("Crypto-shredding complete.")

		return nil
	},
}
