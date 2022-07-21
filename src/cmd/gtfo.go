package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/OnlyF0uR/Hephaestus/src/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type GTFOData struct {
	Functions struct {
		Shell []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"shell"`
		Command []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"command"`
		ReverseShell []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"reverse-shell"`
		NonInteractiveReverseShell []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"non-interactive-reverse-shell"`
		BindShell []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"bind-shell"`
		NonInteractiveBindShell []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"non-interactive-bind-shell"`
		FileUpload []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"file-upload"`
		FileDownload []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"file-download"`
		FileWrite []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"file-write"`
		FileRead []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"file-read"`
		LibraryLoad []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"library-load"`
		Suid []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"suid"`
		Sudo []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"sudo"`
		Capabilities []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"capabilities"`
		LimitedSuid []struct {
			Description string `yaml:"description"`
			Code        string `yaml:"code"`
		} `yaml:"limited-suid"`
	} `yaml:"functions"`
}

func init() {
	rootCmd.AddCommand()
}

var gtfoCmd = &cobra.Command{
	Use:   "url [BINARY]",
	Short: "Access GTFObins",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No binary was provided." + utils.Reset)
			return
		}

		bin := strings.ToLower(args[0])

		res, ex := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/arp.m://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/"+bin+".md", nil)
		if ex != nil {
			fmt.Println(utils.Red + "Could not make GET-request." + utils.Reset)
			return
		}

		if res.Response.StatusCode != 200 {
			fmt.Println(utils.Red + "Invalid binary file." + utils.Reset)
			return
		}

		body, ex := ioutil.ReadAll(res.Body)
		if ex != nil {
			fmt.Println(utils.Red + "Could not read body." + utils.Reset)
			return
		}

		parsed := GTFOData{}
		ex = yaml.Unmarshal([]byte(body), &parsed)
		if ex != nil {
			fmt.Println(utils.Red + "Could not parse yaml." + utils.Reset)
			return
		}

		fmt.Printf("--- t:\n%v\n\n", parsed)
	},
}
