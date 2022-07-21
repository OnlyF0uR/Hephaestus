package cmd

import (
	"fmt"
	"strings"

	"github.com/OnlyF0uR/Hephaestus/src/utils"
	"github.com/spf13/cobra"
)

var baseUrl string
var wordlist string
var threads int
var userAgent string
var timeoutDuration int
var maxConnection int
var delay int

func init() {
	rootCmd.AddCommand(fuzzCmd)

	fuzzCmd.Flags().StringVarP(&baseUrl, "url", "u", "", "The URL to scan.")
	fuzzCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "The word list to use")
	fuzzCmd.Flags().IntVarP(&threads, "threads", "t", 12, "The amount of threads to use.")
	fuzzCmd.Flags().StringVarP(&userAgent, "useragent", "a", "hephaestus/" + utils.ApplicationVersion, "Set the User-Agent.")

	fuzzCmd.Flags().IntVar(&timeoutDuration, "timeout", 10000, "The time after which a request is marked timed out. (Miliseconds)")
	fuzzCmd.Flags().IntVar(&maxConnection, "max-con", 500, "Max amount of concurrent connections.")
	fuzzCmd.Flags().IntVar(&delay, "delay", 0, "The delay in between requests. (Miliseconds)")

	fuzzCmd.MarkFlagRequired("url")
	fuzzCmd.MarkFlagRequired("wordlist")
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz [TYPE]",
	Short: "Fuzzer for websites",
	Long:  "Enumeration tool that uses fuzzing on a specified URL.",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No type was provided." + utils.Reset)
			return
		}

		fuzzType := strings.ToLower(args[0])
		if fuzzType == "http" {
			fmt.Println("Coming soon.")
			// ...
		} else if fuzzType == "subdomain" {
			fmt.Println("Coming soon.")
			// ...
		} else {
			fmt.Println(utils.Red + "Invalid fuzz type. (Use: http or subdomain)" + utils.Reset)
		}
	},
}
