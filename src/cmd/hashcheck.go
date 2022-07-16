package cmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cr "github.com/OnlyF0uR/Intrusor/src/crypto"
	"github.com/OnlyF0uR/Intrusor/src/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(hashcheckCmd)
}

var hashcheckCmd = &cobra.Command{
	Use:   "hashcheck [HASH]",
	Short: "Identify the type of a hash",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(utils.Red + "No arguments were provided." + utils.Reset)
			return
		}

		input := strings.Join(args, " ")
		result := cr.IdentifyHash(input)

		if len(result) == 0 {
			fmt.Println(utils.Yellow + "Unable to identify the hash." + utils.Reset)
		} else if len(result) == 1 {
			fmt.Println(utils.Green + "Match: " + utils.White + cr.AlgoNames[result[0]] + utils.Reset)
		} else if len(result) > 2 {
			sort.Slice(result, func(i, j int) bool {
				numA, _ := strconv.Atoi(result[i])
				numB, _ := strconv.Atoi(result[j])
				return numA < numB
			})

			fmt.Println(utils.Green + "\nMost likely:" + utils.Reset)
			fmt.Println(utils.Green + " - " + utils.White + cr.AlgoNames[result[0]] + utils.Reset)
			fmt.Println(utils.Green + " - " + utils.White + cr.AlgoNames[result[1]] + utils.Reset)

			fmt.Println(utils.Green + "\nLess likely:" + utils.Reset)
			for i := 2; i < len(result); i++ {
				fmt.Println(utils.Green + " - " + utils.White + cr.AlgoNames[result[i]] + utils.Reset)
			}

			fmt.Println()
		} else {
			sort.Slice(result, func(i, j int) bool {
				numA, _ := strconv.Atoi(result[i])
				numB, _ := strconv.Atoi(result[j])
				return numA < numB
			})

			fmt.Println("Matches:" + utils.Reset)
			for i := 0; i < len(result); i++ {
				fmt.Println(utils.Green + " - " + utils.White + cr.AlgoNames[result[i]] + utils.Reset)
			}

			fmt.Println()
		}
	},
}
