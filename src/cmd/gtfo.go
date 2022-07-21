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
	rootCmd.AddCommand(gtfoCmd)
}

var gtfoCmd = &cobra.Command{
	Use:   "gtfo [BINARY]",
	Short: "Access GTFObins",
	Run: func(_ *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No binary was provided." + utils.Reset)
			return
		}

		bin := strings.ToLower(args[0])

		req, ex := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/"+bin+".md", nil)
		if ex != nil {
			fmt.Println(utils.Red + "Could not manufacture GET-request." + utils.Reset)
			return
		}

		res, ex := http.DefaultClient.Do(req)
		if ex != nil {
			fmt.Println(utils.Red + "Could bot send GET-request." + utils.Reset)
			return
		}

		if res.StatusCode != 200 {
			fmt.Println(utils.Red + "Invalid binary file." + utils.Reset)
			return
		}

		body, ex := ioutil.ReadAll(res.Body)
		if ex != nil {
			fmt.Println(utils.Red + "Could not read body." + utils.Reset)
			return
		}

		s_body := strings.ReplaceAll(string(body[:]), "---", "")

		parsed := GTFOData{}
		ex = yaml.Unmarshal([]byte(s_body), &parsed)
		if ex != nil {
			fmt.Println(utils.Red + "Could not parse yaml." + utils.Reset)
			return
		}

		// Yeah could, and perhaps should, use reflection here :/
		if len(parsed.Functions.Shell) > 0 {
			outputInfo(parsed.Functions.Shell, "Shell")
		}
		if len(parsed.Functions.Command) > 0 {
			outputInfo(parsed.Functions.Command, "Command")
		}
		if len(parsed.Functions.ReverseShell) > 0 {
			outputInfo(parsed.Functions.ReverseShell, "Reverse shell")
		}
		if len(parsed.Functions.NonInteractiveReverseShell) > 0 {
			outputInfo(parsed.Functions.NonInteractiveReverseShell, "Non-interactive reverse shell")
		}
		if len(parsed.Functions.BindShell) > 0 {
			outputInfo(parsed.Functions.BindShell, "Bind shell")
		}
		if len(parsed.Functions.NonInteractiveBindShell) > 0 {
			outputInfo(parsed.Functions.NonInteractiveBindShell, "Non-interactive bind shell")
		}
		if len(parsed.Functions.FileUpload) > 0 {
			outputInfo(parsed.Functions.FileUpload, "File upload")
		}
		if len(parsed.Functions.FileDownload) > 0 {
			outputInfo(parsed.Functions.FileDownload, "File download")
		}
		if len(parsed.Functions.FileWrite) > 0 {
			outputInfo(parsed.Functions.FileWrite, "File write")
		}
		if len(parsed.Functions.FileRead) > 0 {
			outputInfo(parsed.Functions.FileRead, "File read")
		}
		if len(parsed.Functions.LibraryLoad) > 0 {
			outputInfo(parsed.Functions.LibraryLoad, "Library load")
		}
		if len(parsed.Functions.Suid) > 0 {
			outputInfo(parsed.Functions.Suid, "SUID")
		}
		if len(parsed.Functions.Sudo) > 0 {
			outputInfo(parsed.Functions.Sudo, "Sudo")
		}
		if len(parsed.Functions.Capabilities) > 0 {
			outputInfo(parsed.Functions.Capabilities, "Capabilities")
		}
		if len(parsed.Functions.LimitedSuid) > 0 {
			outputInfo(parsed.Functions.LimitedSuid, "Limited SUID")
		}
	},
}

func outputInfo(info []struct {
	Description string "yaml:\"description\""
	Code        string "yaml:\"code\""
}, title string) {
	fmt.Println(utils.Green + title + ": " + utils.Reset)
	if len(info[0].Description) > 0 {
		fmt.Println(utils.Cyan + "[description]\n" + utils.White + info[0].Description + utils.Reset)
	}
	if len(info[0].Code) > 0 {
		if strings.HasSuffix(info[0].Code, "\n") {
			fmt.Println(utils.Cyan + "[code]\n" + utils.White + info[0].Code + utils.Green + utils.Reset)
		} else {
			fmt.Println(utils.Cyan + "[code]\n" + utils.White + info[0].Code + utils.Green + "\n" + utils.Reset)
		}
	}
}
