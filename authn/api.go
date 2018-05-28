package authn

import (
	"errors"
	"fmt"
)

var (
	// ErrAccountNotFound error
	ErrAccountNotFound = errors.New("User account is not found")
	// ErrAuthnServerError = errors.New("Error")
)

// Account is authn user account
type Account struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Locked   bool   `json:"locked"`
	Deleted  bool   `json:"deleted"`
}

// GetAccount will return the user account
func (ac *Client) GetAccount(UserID string) (Account, error) {
	res := map[string]interface{}{}
	code, err := ac.iclient.get(fmt.Sprintf("/accounts/%s", UserID), &res)
	if err != nil {
		return Account{}, err
	}

	if code == 404 {
		return Account{}, ErrAccountNotFound
	}

	return res["result"].(Account), nil
}

// UpdateAccount will update the user account
func (ac *Client) UpdateAccount() {

}

// LockAccount will lock the user account
func (ac *Client) LockAccount() {

}

// UnlockAccount will unlock the user account
func (ac *Client) UnlockAccount() {

}

// ArchiveAccount will archive the user account
func (ac *Client) ArchiveAccount() {

}

// ImportAccount will import a user account
func (ac *Client) ImportAccount() {

}

func (ac *Client) ExpirePassword() {

}
