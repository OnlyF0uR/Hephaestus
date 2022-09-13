package cmd

import (
	"bufio"
	"fmt"
	"strings"

	"os"

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
	fuzzCmd.Flags().StringVarP(&userAgent, "useragent", "a", "hephaestus/"+utils.ApplicationVersion, "Set the User-Agent.")

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
			if strings.HasSuffix(baseUrl, "/") {
				scanDirectories(baseUrl)
			} else {
				scanDirectories(baseUrl + "/")
			}
		} else if fuzzType == "subdomain" {
			if strings.HasPrefix(baseUrl, ".") {
				scanSubdomains(baseUrl)
			} else {
				scanSubdomains("." + baseUrl)
			}
		} else {
			fmt.Println(utils.Red + "Invalid fuzz type. (Use: http or subdomain)" + utils.Reset)
		}
	},
}

func scanDirectories(url string) {
	f, ex := os.Open(wordlist)
	if ex != nil {
		fmt.Println(utils.Red + "Wordlist not found." + utils.Reset)
		return
	}

	defer f.Close()

	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		ln := scnr.Text()
		url = url + ln

		// Scan url
		// Check for 404 content existance
	}

	if ex = scnr.Err(); ex != nil {
		fmt.Println(utils.Red + "Scan failed." + utils.Reset)
		return
	}
}

func scanSubdomains(url string) {
	f, ex := os.Open(wordlist)
	if ex != nil {
		fmt.Println(utils.Red + "Wordlist not found." + utils.Reset)
		return
	}

	defer f.Close()

	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		ln := scnr.Text()
		url = ln + url

		// Scan domain for existance
	}

	if ex = scnr.Err(); ex != nil {
		fmt.Println(utils.Red + "Scan failed." + utils.Reset)
		return
	}
}
