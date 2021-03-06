package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/blacksails/cgp"
	"github.com/blacksails/ppe"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cgpCmd = &cobra.Command{
	Use:   "cgp",
	Short: "Imports a CGP domain",
	Long: `Imports a Communigate Pro domain.
	If the domain already exists, it is updated from the information found on
	the Communigate Pro server. If the domain does not already exist, you MUST
	provide the required Proofpoint Essentials organization information. See
	the flags of the import command.`,

	Run: func(cmd *cobra.Command, args []string) {
		pp := createPPEClient()
		cg := createCGPClient()

		// We need to ensure that a domain is specified
		domainLogger := log.WithField("domain", orgDomain)
		if orgDomain == "" {
			domainLogger.Fatal("You must specify a domain to import from cgp")
		}

		// 1. Check if domain exists on cgp else abort
		domainLogger.Info("Checking if domain exists on CGP")
		exists, err := cg.Domain(orgDomain).Exists()
		if !exists && err == nil {
			domainLogger.Fatal("Domain does not exist on the CGP server. Please specify the primary domain used on the CGP server. Aliases are not taken into consideration.")
		}
		if err != nil {
			log.WithFields(log.Fields{
				"domain":   orgDomain,
				"cgp-base": viper.Get("cgp-base"),
				"cgp-user": viper.Get("cgp-user"),
				"error":    err,
			}).Fatal("There was a problem checking if domain exists on the CGP server", err)
		}
		domainLogger.Info("Successfully located the domain on the CGP server")

		// 2. Check if domain exists on ppe else create ppe org
		domainLogger.Info("Checking if domain exists on PPE")
		_, err = pp.Domain(orgDomain)
		if _, ok := err.(ppe.UnauthorizedError); ok {
			domainLogger.Warn("Domain does not exist on PPE.")
			domainLogger.Info("Checking if we have required info to create new domain...")
			if orgName == "" {
				domainLogger.Fatal("Organization name is required")
			}
			if orgFirstName == "" {
				domainLogger.Fatal("Admin firstname is required")
			}
			if orgLastName == "" {
				domainLogger.Fatal("Admin lastname is required")
			}
			if orgLicences < 1 {
				domainLogger.Fatal("An organization must have at least 1 license")
			}
			domainLogger.Info("Successfully checked required info")
			fmt.Printf("Name: %s\n", orgName)
			fmt.Printf("Domain: %s\n", orgDomain)
			fmt.Printf("Address: %s\n", orgAddr)
			fmt.Printf("Zip: %s\n", orgAddr)
			fmt.Printf("Country: %s\n", orgCountry)
			fmt.Printf("Phone: %s\n", orgPhone)
			fmt.Printf("Admin Firstname: %s\n", orgFirstName)
			fmt.Printf("Admin Lastname: %s\n", orgLastName)
			fmt.Printf("Admin Email: %s\n", orgEmail)
			fmt.Printf("Package: %s\n", orgPackage)
			if orgTemplate == "" {
				// Fallback to a default template based on package
				defTemplates := viper.GetStringMapString("default-templates")
				switch orgPackage {
				case "beginner", "":
					orgTemplate = defTemplates["beginner"]
				case "business":
					orgTemplate = defTemplates["business"]
				case "advanced":
					orgTemplate = defTemplates["advanced"]
				case "professional":
					orgTemplate = defTemplates["professional"]
				}
			}
			fmt.Printf("Package Template ID: %s\n", orgTemplate)
			fmt.Printf("User Licences: %v\n", orgLicences)
			if !askForConfirmation("Create organization with the above information?") {
				domainLogger.Fatal("Aborting...")
			}
			apiDom := strings.Split(viper.GetString("api-user"), "@")[1]
			apiOrg, err := pp.Organization(apiDom)
			if err != nil {
				log.WithField("error", err).Fatal("Couldn't determine api user organization")
			}
			domainLogger.Info("Creating organization...")
			newOrg := ppe.NewOrganization{
				PrimaryDomain: orgDomain,
				Name:          orgName,
				Domains: []ppe.NewOrgDomain{
					{
						Name:       orgDomain,
						Transports: []string{viper.GetString("cgp-base")},
					},
				},
				AdminUser: ppe.NewUser{
					Firstname:    orgFirstName,
					Lastname:     orgLastName,
					PrimaryEmail: orgEmail,
				},
				UserLicenses:      orgLicences,
				WWW:               orgDomain,
				Address:           orgAddr,
				Postcode:          orgZip,
				Country:           orgCountry,
				Phone:             orgPhone,
				LicencingPackage:  orgPackage,
				AccountTemplateID: orgTemplate,
			}
			if err = apiOrg.CreateOrganization(newOrg); err != nil {
				log.WithField("error", err).Fatal("Error creating organization")
			}
			domainLogger.Info("Successfully created organization")
		} else {
			domainLogger.Info("Successfully located the domain on PPE")
		}

		// 3. Sync CGP domain with PPE
		domainLogger.Info("Starting domain syncronization")

		// - Gather list of domains that should be present on PPE
		domainLogger.Info("Gathering domains from CGP")
		cgpDoms := []string{orgDomain}
		cgpAs, err := cg.Domain(orgDomain).Aliases()
		if err != nil {
			domainLogger.Fatal("There was a problem fetching domain aliases from CGP")
		}
		for _, a := range cgpAs {
			cgpDoms = append(cgpDoms, a)
		}
		log.WithField("domains", cgpDoms).Info("Successfully fetched CGP domains")

		// - Gather list of domains actually on PPE
		domainLogger.Info("Gathering domains from PPE")
		ppeOrg, err := pp.Organization(orgDomain)
		if err != nil {
			log.WithField("error", err).Fatal("There was a problem fetching PPE organization")
		}
		ppeDoms, err := ppeOrg.Domains()
		if err != nil {
			log.WithField("error", err).Fatal("There was a problem fetching PPE domains")
		}
		ppeDomStrs := make([]string, len(ppeDoms))
		for i, d := range ppeDoms {
			ppeDomStrs[i] = d.Name
		}
		log.WithField("domains", ppeDomStrs).Info("Successfully fetched PPE domains")

		// Compare results and build list of differences
		log.Info("Checking if there are CGP domains missing in PPE")
		var missingDoms []string
		for _, cgpD := range cgpDoms {
			found := false
			for _, ppeD := range ppeDomStrs {
				if ppeD == cgpD {
					found = true
					break
				}
			}
			domLogger := log.WithField("domain", cgpD)
			if !found {
				domLogger.Info("Domain missing on PPE")
				missingDoms = append(missingDoms, cgpD)
			} else {
				domLogger.Info("Domain exists on PPE")
			}
		}
		log.WithField("domains", missingDoms).Info("Successfully built list of missing domains")

		// - Add missing domains. Prompt user to accept creation of different domains.
		for _, dom := range missingDoms {
			ok := askForConfirmation(fmt.Sprintf("Add %s to PPE?", dom))
			if !ok {
				continue // Skip domain
			}
			log.WithField("domain", dom).Info("Creating domain")
			newDom := ppe.NewDomain{
				DomainName:  dom,
				Destination: viper.GetString("cgp-base"),
				IsRelay:     1,
			}
			err := ppeOrg.CreateDomain(newDom)
			if err != nil {
				log.WithField("error", err).Fatal("Couldn't create domain")
			}
			log.WithField("domain", dom).Info("Successfully created domain")
		}

		// Gather list of accounts that should be present on PPE
		domainLogger.Info("Fetching PPE accounts")
		cgpAccs, err := cg.Domain(orgDomain).Accounts()
		if err != nil {
			log.WithField("error", err).Fatal("Error when fetching accounts from CGP")
		}
		domainLogger.Info("Succesfully fetched CGP accounts")

		// Gather list of accounts actually on PPE
		domainLogger.Info("Fetching PPE accounts")
		ppeAccs, err := ppeOrg.Users()
		if err != nil {
			log.WithField("error", err).Fatal("Error when fetching accounts from PPE")
		}
		domainLogger.Info("Successfully fetched PPE accounts")

		// Gather list of PPE domains
		domainLogger.Info("Fetching PPE domains")
		ppeDoms, err = ppeOrg.Domains()
		if err != nil {
			log.WithError(err).Fatal("Error when fetching domains from PPE")
		}
		domainLogger.Info("Successfully fetched PPE domains")

		// Compare lists of fetch accounts, add accounts.
		for _, cgpA := range cgpAccs {

			// Check if account is missing
			found := false
			for _, ppeA := range ppeAccs {
				if cgpA.Email() == ppeA.Email {
					found = true
					break
				}
			}
			accLogger := log.WithField("account", cgpA.Email())
			if !found {
				// Create account if missing
				accLogger.Info("Creating account")
				err := ppeOrg.CreateUser(ppe.NewUser{PrimaryEmail: cgpA.Email()})
				if err != nil {
					log.WithField("error", err).Fatal("Error when trying to create account")
				}
				accLogger.Info("Successfully created account")
			} else {
				accLogger.Info("Account already exists on PPE")
			}

			// Check if account has registered the correct aliases
			accLogger.Info("Fetching CGP account aliases")
			cgpAlis, err := cgpA.Aliases()
			if err != nil {
				log.WithFields(log.Fields{
					"account": cgpA.Email(),
					"error":   err,
				}).Fatal("Error fetching account CGP aliases")
			}
			accLogger.Info("Successfully fetched CGP account aliases")
			accLogger.Info("Fetching PPE account")
			ppeAcc, err := ppeOrg.User(cgpA.Email())
			if err != nil {
				log.WithFields(log.Fields{
					"account": cgpA.Email(),
					"error":   err,
				}).Fatal("Error fetching PPE account")
			}
			accLogger.Info("Successfully fetched PPE account")
			aliStatuses := make(map[string]int, len(cgpAlis))
			aliases := make([]string, 0)
			for _, ppeD := range ppeDoms {
				for _, cgpAli := range cgpAlis {
					ali := fmt.Sprintf("%s@%s", cgpAli.Name, ppeD.Name)
					aliStatuses[ali] = aliStatuses[ali] + 1
					aliases = append(aliases, ali)
				}
			}
			for _, ppeAli := range ppeAcc.Aliases {
				aliStatuses[ppeAli] = aliStatuses[ppeAli] + 2
			}
			syncNeeded := false
			for _, v := range aliStatuses {
				if v != 3 {
					syncNeeded = true
					break
				}
			}

			// Sync account aliases if needed
			if syncNeeded {
				accLogger.Info("Found unsynced account aliases. Starting syncronization")
				uc := ppe.UserChange{PrimaryEmail: cgpA.Email(), AliasEmails: aliases}
				err = ppeOrg.UpdateUser(uc)
				if err != nil {
					log.WithFields(log.Fields{
						"error":   err,
						"account": cgpA.Email(),
						"aliases": aliases,
					}).Fatal("Error when updating account aliases")
				}
				accLogger.Info("Successfully updated account aliases")
			} else {
				accLogger.Info("Aliases are already fully synced")
			}
		}

		// Add forwarders as normal accounts
		domainLogger.Info("Fetching CGP forwarders")
		cgpFws, err := cg.Domain(orgDomain).Forwarders()
		if err != nil {
			domainLogger.WithError(err).Fatal("Error when fetching CGP forwarders")
		}
		domainLogger.Info("Successfully fetched forwarders")
		for _, cgpFw := range cgpFws {
			fwLogger := domainLogger.WithField("forwarder", cgpFw.Name)
			// Check if forwarder already exists
			found := false
			for _, ppeA := range ppeAccs {
				if cgpFw.Email() == ppeA.Email {
					found = true
					break
				}
			}
			if found {
				fwLogger.Info("Creating PPE account for forwarder")
				err := ppeOrg.CreateUser(ppe.NewUser{PrimaryEmail: cgpFw.Email()})
				if err != nil {
					fwLogger.WithError(err).Fatal("Error when creating user for forwarder")
				}
				fwLogger.Info("Successfully created PPE user for forwarder")
			} else {
				fwLogger.Info("PPE user for forwarder already exists")
			}

			fwLogger.Info("Fetching PPE user for forwarder")
			ppeAcc, err := ppeOrg.User(cgpFw.Email())
			if err != nil {
				fwLogger.WithError(err).Fatal("Error when fetching PPE user for forwarder")
			}
			fwLogger.Info("Successfully fetched PPE user for forwarder")

			aliases := make([]string, 0)
			for _, ppeD := range ppeDoms {
				if ppeD.Name == cgpFw.Domain.Name {
					continue // This is the primary email so no need to create an alias
				}
				aliases = append(aliases, fmt.Sprintf("%s@%s", cgpFw.Name, ppeD.Name))
			}
			syncNeeded := false
			for _, ali := range aliases {
				found := false
				for _, ppeAli := range ppeAcc.Aliases {
					if ali == ppeAli {
						found = true
					}
				}
				if !found {
					syncNeeded = true
				}
			}
			if syncNeeded {
				fwLogger.Info("Found missing user alias(es). Starting syncronization")
				uc := ppe.UserChange{PrimaryEmail: cgpFw.Email(), AliasEmails: aliases}
				err = ppeOrg.UpdateUser(uc)
				if err != nil {
					fwLogger.WithField("aliases", aliases).WithError(err).Fatal("Error updating PPE user aliases")
				}
				fwLogger.WithField("aliases", aliases).Info("Successfully updated PPE user")
			}
		}

		// TODO: Add groups as functional accounts
		// TODO: Add mailing lists as functional accounts
	},
}

func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/n]: ", s)
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}

func createCGPClient() *cgp.CGP {
	base := viper.GetString("cgp-base")
	user := viper.GetString("cgp-user")
	pass := viper.GetString("cgp-pass")
	cgpLogger := log.WithFields(log.Fields{"cgp-base": base, "cgp-user": user})
	if base == "" {
		cgpLogger.Fatal("Please specify cgp-base, so we know where to connect to Communigate Pro")
	}
	if user == "" {
		cgpLogger.Fatal("Please specify cgp-user. This is the user we will use to make requests to Communigate Pro")
	}
	if pass == "" {
		cgpLogger.Fatal("Please specify cgp-pass. This is the pass we will use to make requests to Communigate Pro")
	}
	return cgp.New(base, user, pass)
}

func init() {
	importCmd.AddCommand(cgpCmd)
	cgpCmd.Flags().StringP("cgp-base", "B", "", "CGP host without protocol (we force https!)")
	viper.BindPFlag("cgp-base", cgpCmd.Flags().Lookup("cgp-base"))
	cgpCmd.Flags().StringP("cgp-user", "U", "", "CGP user for CGP server auth")
	viper.BindPFlag("cgp-user", cgpCmd.Flags().Lookup("cgp-user"))
	cgpCmd.Flags().StringP("cgp-pass", "P", "", "CGP user password for CGP server auth")
	viper.BindPFlag("cgp-pass", cgpCmd.Flags().Lookup("cgp-pass"))
}
