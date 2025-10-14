package main

import (
	"github.com/fedi-e2ee/pkd-server-go/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	configFile, _ := cmd.Flags().GetString("config")
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
