// Package main is the dontguess CLI entry point.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the build version, injected at build time via ldflags:
// -X main.Version=v1.2.3
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "dontguess",
	Short: "DontGuess — token-work exchange operator CLI",
	Long: `dontguess — operator CLI for the DontGuess token-work exchange.

Exchange state (inventory, orders, matches, settlements) is derived from
the message log.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}

var jsonOutput bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
