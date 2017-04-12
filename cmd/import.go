package cmd

import (
	"github.com/spf13/cobra"
)

var (
	orgName      string
	orgAddr      string
	orgZip       string
	orgCountry   string
	orgFirstName string
	orgLastName  string
	orgEmail     string
	orgDomain    string
	orgLicences  int
	orgPhone     string
	orgPackage   string
	orgTemplate  string
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Imports data into proofpoint from different mailservers",
	Long: `The import command has a suite of subcommands for importing data
	from different mailservers.`,
}

func init() {
	RootCmd.AddCommand(importCmd)
	importCmd.PersistentFlags().StringVar(&orgName, "name", "", "Name of organization")
	importCmd.PersistentFlags().StringVar(&orgAddr, "addr", "", "Address of organization")
	importCmd.PersistentFlags().StringVar(&orgZip, "zip", "", "Zip code of organization")
	importCmd.PersistentFlags().StringVar(&orgCountry, "country", "DK", "Country code of organization. eg. DK for denmark")
	importCmd.PersistentFlags().StringVar(&orgFirstName, "firstname", "", "First name of organization admin account")
	importCmd.PersistentFlags().StringVar(&orgLastName, "lastname", "", "Last name of organization admin account")
	importCmd.PersistentFlags().StringVar(&orgEmail, "email", "", "Email of organization admin account")
	importCmd.PersistentFlags().StringVar(&orgDomain, "domain", "", "Primary organization domain")
	importCmd.PersistentFlags().IntVar(&orgLicences, "licences", 1, "Number of user licenses")
	importCmd.PersistentFlags().StringVar(&orgPhone, "phone", "", "Phone number of organization")
	importCmd.PersistentFlags().StringVar(&orgPackage, "package", "beginner", "PPE package. Must be one of beginner, business, advanced or professional.")
	importCmd.PersistentFlags().StringVar(&orgTemplate, "template", "", "Template ID for organization creation")
}
