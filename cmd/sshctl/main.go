// cmd/sshctl/main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"sshproxy/cmd/sshctl/command"
	"sshproxy/pkg/storage"
)

var (
	cfgFile string
	dbPath  string
)

var rootCmd = &cobra.Command{
	Use:   "sshctl",
	Short: "SSH Proxy Management Tool",
	Long:  `Manage SSH proxy connections, HASSH fingerprints, and blocklists.`,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sshctl.yaml)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "ssh_connections.db", "SQLite database path")

	err := viper.BindPFlag("db", rootCmd.PersistentFlags().Lookup("db"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".sshctl")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	// Initialize database
	db, err := gorm.Open(sqlite.Open(viper.GetString("db")), &gorm.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}

	repo, err := storage.NewRepository(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize repository: %v\n", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(command.NewListCmd(repo))
	rootCmd.AddCommand(command.NewBlockCmd(repo))
	rootCmd.AddCommand(command.NewUnblockCmd(repo))
	rootCmd.AddCommand(command.NewLogCmd(repo))
	rootCmd.AddCommand(command.NewStatsCmd(repo))
	rootCmd.AddCommand(command.NewTUICmd(repo))
	rootCmd.AddCommand(command.NewReloadCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
