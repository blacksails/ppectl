package cmd

import (
	log "github.com/Sirupsen/logrus"
	"github.com/blacksails/ppe"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ppectl",
	Short: "Proofpoint Essentials CLI",
	Long: `ppectl is a command line interface to the excellent email security
	service Proofpoint Essentials.`,

	Run: func(cmd *cobra.Command, args []string) {
		createPPEClient()
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Setup flags
	RootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.ppectl.yaml)")
	RootCmd.PersistentFlags().StringP("api-base", "a", "eu1.proofpointessentials.com", "API base that PPE requests are sent to")
	viper.BindPFlag("api-base", RootCmd.PersistentFlags().Lookup("api-base"))
	RootCmd.PersistentFlags().StringP("api-user", "u", "", "PPE user which requests are sent with")
	viper.BindPFlag("api-user", RootCmd.PersistentFlags().Lookup("api-user"))
	RootCmd.PersistentFlags().StringP("api-pass", "p", "", "Password of PPE user which requests are sent with")
	viper.BindPFlag("api-pass", RootCmd.PersistentFlags().Lookup("api-pass"))
}

func createPPEClient() *ppe.PPE {
	var base, user, pass string
	base = viper.GetString("api-base")
	user = viper.GetString("api-user")
	pass = viper.GetString("api-pass")
	ppeLogger := log.WithFields(log.Fields{"api-base": base, "api-user": user, "api-pass": pass})
	if base == "" {
		ppeLogger.Fatal("Please specify an api-base to send requests to")
	}
	if user == "" {
		ppeLogger.Fatal("Please specify an api-user to send requests with")
	}
	if pass == "" {
		ppeLogger.Fatal("Please specify an api-pass to send requests with")
	}
	return ppe.New(base, user, pass)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".ppectl") // name of config file (without extension)
	viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithField("config", viper.ConfigFileUsed()).Info("Using config file")
	}
}
