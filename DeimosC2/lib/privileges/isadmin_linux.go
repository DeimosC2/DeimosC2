// +build linux

package privileges

import "os/user"

//AdminOrElevated checks to see if the user is admin and if it is elevated
func AdminOrElevated() (elevated bool, admin bool) {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	userID := user.Uid

	if userID == "0" {
		admin = true
	} else {
		admin = false
	}

	elevated = false

	return elevated, admin
}
