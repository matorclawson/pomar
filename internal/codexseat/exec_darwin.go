package codexseat

import "errors"

func hardenActor() error    { return errors.New("Codex seat exec is Linux guest only") }
func checkTTYPolicy() error { return errors.New("guest TIOCSTI policy is Linux only") }

func noNewPrivileges() error { return errors.New("guest no_new_privs is Linux only") }
