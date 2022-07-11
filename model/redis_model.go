package model

type TokenDetails struct {
	AccessToken string
	AccessUuid  string
	AtExpires   int64
}

type AccessDetail struct {
	AccessUuid string
	Username   string
}
