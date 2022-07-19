package cmd

import (
	"fmt"

	"github.com/OnlyF0uR/Intrusor/src/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version number",
	Long:  "Obtain the current version number of the application",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(utils.Green + "Current version: " + utils.White + "v" + utils.ApplicationVersion + utils.Reset)
	},
}
