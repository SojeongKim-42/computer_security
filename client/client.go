package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	UserUuid         uuid.UUID
	Username         string
	Password         []byte
	SaltPBK          []byte
	MasterFileMap    map[string]uuid.UUID
	AccessFileMap    map[string]uuid.UUID
	AccessFileKeyMap map[string][]byte
	InviteDecKey     userlib.PKEDecKey
	InviteSignKey    userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	FileContent []byte
}

type AccessFile struct {
	Filename string
	FileUuid uuid.UUID
	FileKey  []byte
	//WhoInvitedMe string
	InvitedWho map[string]uuid.UUID
	FileTag    []byte
}

type Invitation struct {
	Filename       string
	FileKey        []byte
	Recipient      string
	FileUuid       uuid.UUID
	AccessFileUuid uuid.UUID
}

type InvitationInfo struct {
	EncryptedInvitation  []byte
	SignedInvitation     []byte
	InvitationDecryptKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.
func UpdateUser(userdata *User) (new_userdata *User) {
	new_userdata = userdata
	h_username := userlib.Hash([]byte(userdata.Username))
	user_uuid, _ := uuid.FromBytes(h_username[:16])
	user_encrypted, ok1 := userlib.DatastoreGet(user_uuid)
	if !ok1 {
		fmt.Println("There is no initialized user for the given username.")
		return
	}

	user_decrypt_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
	user_bytes := userlib.SymDec(user_decrypt_key, user_encrypted) //Decrypt user structure
	err := json.Unmarshal(user_bytes, &new_userdata)               //Retrieve the user structure
	if err != nil {
		fmt.Println(strings.ToTitle("Making user struct error"))
		return
	}
	return new_userdata
}

func UploadUser(userdata *User) {
	user_bytes, err := json.Marshal(&userdata)
	if err != nil {
		return
	}
	user_encrypt_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
	user_encrypted := userlib.SymEnc(user_encrypt_key, userlib.RandomBytes(16), user_bytes)
	userlib.DatastoreDelete(userdata.UserUuid)
	userlib.DatastoreSet(userdata.UserUuid, user_encrypted)
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Error handling
	if username == "" {
		return nil, errors.New(strings.ToTitle("Empty usename"))
	}

	h_username := userlib.Hash([]byte(username))
	user_uuid, _ := uuid.FromBytes(h_username[:16])

	_, ok := userlib.DatastoreGet(user_uuid)
	if ok {
		return nil, errors.New("Same username exists.")
	}

	var userdata = User{
		UserUuid:         user_uuid,
		Username:         username,
		Password:         []byte(password),
		SaltPBK:          []byte(username), //Salt used to enc/dec user structure -> made by username
		MasterFileMap:    make(map[string]uuid.UUID),
		AccessFileMap:    make(map[string]uuid.UUID),
		AccessFileKeyMap: make(map[string][]byte),
	}

	//Generating Public Key (RSA) used to decrypting the invitation user got from others
	//Others can encrypt the invitation by public key
	rsa_encrypt_key, rsa_decrypt_key, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("Public Key Encrypt Generate error"))
	}
	userlib.KeystoreSet("rsa_enc"+userdata.Username, rsa_encrypt_key)
	userdata.InviteDecKey = rsa_decrypt_key

	//Generating Digital Sign Key used to signing the invitation that user gives to others
	//Others can verify the sign by public key
	digital_sign_key, digital_verify_key, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("Digital Sign Key Generate error"))
	}
	userlib.KeystoreSet("ds_verify"+userdata.Username, digital_verify_key)
	userdata.InviteSignKey = digital_sign_key
	user_bytes, err := json.Marshal(&userdata) //Make json of User struct
	if err != nil {
		return nil, errors.New(strings.ToTitle("Making json error"))
	}

	user_encrypt_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)          //Make a key of Encrypting whole User struct by password and salt
	user_encrypted := userlib.SymEnc(user_encrypt_key, userlib.RandomBytes(16), user_bytes) //Encrypts it and upload to the DataStore

	user_password_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
	user_tag, err := userlib.HMACEval(user_password_key, user_encrypted) //create user_tag
	if err != nil {
		return nil, errors.New(strings.ToTitle("create HMAC error"))
	}
	user_tag_uuid, _ := uuid.FromBytes(h_username[16:]) //create user_tag_uuid
	userlib.DatastoreSet(user_tag_uuid, user_tag)       //store user_tag
	userlib.DatastoreSet(userdata.UserUuid, user_encrypted)

	return &userdata, nil
}

func VerifyUserChanged(userdata *User, username string, password string) (err error) {
	h_username := userlib.Hash([]byte(username))
	user_uuid, _ := uuid.FromBytes(h_username[:16])
	user_tag_uuid, _ := uuid.FromBytes(h_username[16:])
	user_password_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)

	getUser, ok := userlib.DatastoreGet(user_uuid) //Get User Struct from Datastore
	if !ok {
		return errors.New(strings.ToTitle("user not found"))
	}
	getUserTag, ok := userlib.DatastoreGet(user_tag_uuid) //Get UserTag Struct from Datastore
	if !ok {
		return errors.New(strings.ToTitle("user_tag not found"))
	}
	check_user_hash, err := userlib.HMACEval(user_password_key, getUser) // create user_tag of downloaded
	if err != nil {
		return errors.New(strings.ToTitle("create downloaded user HMAC error"))
	}

	check := userlib.HMACEqual(getUserTag, check_user_hash)
	if !check {
		return errors.New(strings.ToTitle("Someone tampered User data"))
	}
	return 
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	h_username := userlib.Hash([]byte(username))
	user_uuid, _ := uuid.FromBytes(h_username[:16])

	var userdata User
	user_encrypted, ok2 := userlib.DatastoreGet(user_uuid) //Download the user structure in the DataStore
	if !ok2 {
		return nil, errors.New(strings.ToTitle("User not found"))
	}
	user_decrypt_key := userlib.Argon2Key([]byte(password), []byte(username), 16) //Make decrypt key by password
	user_bytes := userlib.SymDec(user_decrypt_key, user_encrypted)                //Decrypt user structure
	err = json.Unmarshal(user_bytes, &userdata)                                   //Retrieve the user structure
	if err != nil {
		return nil, errors.New(strings.ToTitle("Making user struct error"))
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	VerifyUserChanged(userdata, userdata.Username, string(userdata.Password))
	userdata = UpdateUser(userdata)
	if accessFile_uuid, exist := userdata.AccessFileMap[filename]; exist {

		//get file's key from accessFile
		accessFile_encrypted_bytes, ok := userlib.DatastoreGet(accessFile_uuid)
		if !ok {
			return errors.New(strings.ToTitle("File struct Not Found"))
		}
		var accessFile AccessFile
		err = json.Unmarshal(accessFile_encrypted_bytes, &accessFile)
		if err != nil {
			return errors.New(strings.ToTitle("File struct convert error"))
		}
		accessFile_decrypt_key := userdata.AccessFileKeyMap[filename]
		accessFile.FileKey = userlib.SymDec(accessFile_decrypt_key, accessFile.FileKey)

		//file download -> edit content -> upload
		var file File
		file_decrypt_key := accessFile.FileKey
		file_uuid := accessFile.FileUuid
		file_down_encrypted, ok := userlib.DatastoreGet(file_uuid)
		if !ok {
			return errors.New(strings.ToTitle("File Not Found"))
		}
		file_decrypted_bytes := userlib.SymDec(file_decrypt_key, file_down_encrypted)
		err = json.Unmarshal(file_decrypted_bytes, &file)
		if err != nil {
			return errors.New(strings.ToTitle("File convert error"))
		}
		file.FileContent = content
		file_edited_bytes, err := json.Marshal(&file)
		if err != nil {
			return errors.New(strings.ToTitle("File convert error"))
		}
		user_password_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
		accessFile.FileTag, err = userlib.HMACEval(user_password_key, file_edited_bytes) //update FileTag and store
		if err != nil {
			return errors.New(strings.ToTitle("create HMAC error"))
		}
		file_up_encrypted := userlib.SymEnc(accessFile.FileKey, userlib.RandomBytes(16), file_edited_bytes)
		userlib.DatastoreDelete(accessFile.FileUuid)
		userlib.DatastoreSet(accessFile.FileUuid, file_up_encrypted)

		UploadUser(userdata)
	}

	var file = File{
		FileContent: content,
	}

	file_encrypt_key := userlib.RandomBytes(16) //File Key. Encrypt File Struct and Stored at accFile.Keys
	file_bytes, err := json.Marshal(&file)      // Make json of file structure
	file_encrypted := userlib.SymEnc(file_encrypt_key, userlib.RandomBytes(16), file_bytes)

	var accessFile = AccessFile{
		Filename:   filename,
		FileUuid:   uuid.New(),
		FileKey:    file_encrypt_key,
		InvitedWho: make(map[string]uuid.UUID),
	}
	accessFile_encrypt_key := userlib.RandomBytes(16) // accFile struct Encrypt Key. stored at userdata.AccessFileKeyMap
	accessFile.FileKey = userlib.SymEnc(accessFile_encrypt_key, userlib.RandomBytes(16), accessFile.FileKey)

	accessFile_encrypted_bytes, err := json.Marshal(&accessFile) // Make json of accFile structure
	if err != nil {
		return errors.New(strings.ToTitle("Making json error"))
	}

	user_password_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
	accessFile.FileTag, err = userlib.HMACEval(user_password_key, file_bytes) //create FileTag and store
	if err != nil {
		return errors.New(strings.ToTitle("create HMAC error"))
	}

	accessFile_uuid := uuid.New() //UUID of AccessFile struct
	userdata.AccessFileKeyMap[filename] = accessFile_encrypt_key
	userdata.AccessFileMap[filename] = accessFile_uuid
	userdata.MasterFileMap[filename] = accessFile_uuid // add file in MasterFileMap

	userlib.DatastoreSet(accessFile.FileUuid, file_encrypted)
	userlib.DatastoreSet(accessFile_uuid, accessFile_encrypted_bytes)

	UploadUser(userdata)

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	VerifyUserChanged(userdata, userdata.Username, string(userdata.Password))
	userdata = UpdateUser(userdata)

	accessFile_uuid, exist := userdata.AccessFileMap[filename]
	if !exist { //check if user can access the file
		return errors.New(strings.ToTitle("You don't have authority to this file"))
	}

	accessFile_encrypted_bytes, ok := userlib.DatastoreGet(accessFile_uuid) //get accessFile from Datastore
	if !ok {
		return errors.New(strings.ToTitle("File struct Not Found"))
	}
	var accessFile AccessFile
	err := json.Unmarshal(accessFile_encrypted_bytes, &accessFile)
	if err != nil {
		return errors.New(strings.ToTitle("Unmarshal access file struct error"))
	}
	accessFile_decrypt_key := userdata.AccessFileKeyMap[filename] //get decrypt key of accessFile struct
	accessFile.FileKey = userlib.SymDec(accessFile_decrypt_key, accessFile.FileKey)

	var file File
	file_decrypt_key := accessFile.FileKey
	file_uuid := accessFile.FileUuid
	file_down_encrypted, ok := userlib.DatastoreGet(file_uuid) //get file from Datastore
	if !ok {
		return errors.New(strings.ToTitle("File Not Found"))
	}
	file_decrypted_bytes := userlib.SymDec(file_decrypt_key, file_down_encrypted)
	err = json.Unmarshal(file_decrypted_bytes, &file)

	file.FileContent = append(file.FileContent, content...) //File content append
	file_edited_bytes, err := json.Marshal(&file)
	if err != nil {
		return errors.New(strings.ToTitle("File convert error"))
	}
	user_password_key := userlib.Argon2Key(userdata.Password, userdata.SaltPBK, 16)
	accessFile.FileTag, err = userlib.HMACEval(user_password_key, file_edited_bytes) //update FileTag and store
	if err != nil {
		return errors.New(strings.ToTitle("create HMAC error"))
	}
	file_up_encrypted := userlib.SymEnc(accessFile.FileKey, userlib.RandomBytes(16), file_edited_bytes)
	userlib.DatastoreDelete(accessFile.FileUuid)
	userlib.DatastoreSet(accessFile.FileUuid, file_up_encrypted)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	VerifyUserChanged(userdata, userdata.Username, string(userdata.Password))
	userdata = UpdateUser(userdata)

	accessFile_uuid, exist := userdata.AccessFileMap[filename]
	if !exist { //check if user can accessthe file
		return nil, errors.New(strings.ToTitle("You don't have authority to this file"))
	}

	accessFile_encrypted_bytes, ok := userlib.DatastoreGet(accessFile_uuid) //get accessFile from Datastore
	if !ok {
		return nil, errors.New(strings.ToTitle("File struct Not Found"))
	}
	var accessFile AccessFile
	err = json.Unmarshal(accessFile_encrypted_bytes, &accessFile)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Unmarshal access file struct error"))
	}
	accessFile_decrypt_key := userdata.AccessFileKeyMap[filename] //get decrypt key of accessFile struct
	accessFile.FileKey = userlib.SymDec(accessFile_decrypt_key, accessFile.FileKey)

	var file File
	file_decrypt_key := accessFile.FileKey
	file_uuid := accessFile.FileUuid
	file_down_encrypted, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return nil, errors.New(strings.ToTitle("File Not Found"))
	}
	file_decrypted_bytes := userlib.SymDec(file_decrypt_key, file_down_encrypted)
	err = json.Unmarshal(file_decrypted_bytes, &file)
	if err != nil {
		return nil, errors.New(strings.ToTitle("File convert error"))
	}
	return file.FileContent, err
}


func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	userdata = UpdateUser(userdata)

	//Get AccessFile struct, and get the file key & file uuid
	accessFile_uuid, ok1 := userdata.AccessFileMap[filename]
	if !ok1 {
		return invitationPtr, errors.New(strings.ToTitle("User cannot access the file error"))
	}
	accessFile_encrypted_bytes, ok2 := userlib.DatastoreGet(accessFile_uuid)
	if !ok2 {
		return invitationPtr, errors.New(strings.ToTitle("No file in datastore error"))
	}

	accessFile_decrypt_key := userdata.AccessFileKeyMap[filename] //get decrypt key of accessFile struct
	var accessFile AccessFile
	err = json.Unmarshal(accessFile_encrypted_bytes, &accessFile) //Retrieve the user structure
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Unmarshal access file error"))
	}
	file_key := userlib.SymDec(accessFile_decrypt_key, accessFile.FileKey)
	recipient_accessFile_uuid := uuid.New()
	accessFile.InvitedWho[recipientUsername] = recipient_accessFile_uuid

	accessFile_encrypted_bytes, err = json.Marshal(&accessFile)
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Marshal access file error"))
	}
	userlib.DatastoreDelete(accessFile_uuid)
	userlib.DatastoreSet(accessFile_uuid, accessFile_encrypted_bytes)

	//Make invitation -> encrypt and upload
	var invitation = Invitation{
		Filename:       filename,
		FileKey:        file_key,
		FileUuid:       accessFile.FileUuid,
		Recipient:      recipientUsername,
		AccessFileUuid: recipient_accessFile_uuid,
	}

	invitation_bytes, err := json.Marshal(&invitation)
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Making json error"))
	}

	invitation_randomkey := userlib.RandomBytes(16)
	invitation_encrypted := userlib.SymEnc(invitation_randomkey, userlib.RandomBytes(16), invitation_bytes)

	rsa_encrypt_key, ok3 := userlib.KeystoreGet("rsa_enc" + recipientUsername)
	if !ok3 {
		return invitationPtr, errors.New(strings.ToTitle("No invitation public key error"))
	}
	invitation_randomkey_encrypted, err := userlib.PKEEnc(rsa_encrypt_key, invitation_randomkey) //encrypt the randomkey
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Encrypting randomkey error"))
	}
	signed_invitation, err := userlib.DSSign(userdata.InviteSignKey, invitation_encrypted)
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Signing invitation error"))
	}

	var invitation_info = InvitationInfo{
		EncryptedInvitation:  invitation_encrypted,
		InvitationDecryptKey: invitation_randomkey_encrypted,
		SignedInvitation:     signed_invitation,
	}
	invitation_info_bytes, err := json.Marshal(&invitation_info) //Make json of User struct
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("Marshal invitation info error"))
	}

	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, invitation_info_bytes)
	UploadUser(userdata)
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userdata = UpdateUser(userdata)

	invitation_info_bytes, ok1 := userlib.DatastoreGet(invitationPtr)
	if !ok1 {
		return errors.New(strings.ToTitle("No such invitation in datastore error"))
	}
	var invitation_info InvitationInfo
	err := json.Unmarshal(invitation_info_bytes, &invitation_info)
	if err != nil {
		return errors.New(strings.ToTitle("Unmarshal invitation info error"))
	}
	ds_verify_key, ok2 := userlib.KeystoreGet("ds_verify" + userdata.Username)
	if !ok2 {
		return errors.New(strings.ToTitle("No ds verify key"))
	}
	userlib.DSVerify(ds_verify_key, invitation_info.EncryptedInvitation, invitation_info.SignedInvitation)
	if err != nil {
		return errors.New(strings.ToTitle("Sign does not match!"))
	}

	invitation_randomkey, err := userlib.PKEDec(userdata.InviteDecKey, invitation_info.InvitationDecryptKey)
	if err != nil {
		return errors.New(strings.ToTitle("Decrypting invitation key error"))
	}

	invitation_encrypted := invitation_info.EncryptedInvitation
	invitation_bytes := userlib.SymDec(invitation_randomkey, invitation_encrypted)

	var invitation Invitation
	err = json.Unmarshal(invitation_bytes, &invitation)
	if err != nil {
		return errors.New(strings.ToTitle("Unmarshal invitation error"))
	}

	//Making the AccessFile Structure
	var accessFile = AccessFile{
		Filename: filename,
		FileUuid: invitation.FileUuid,
		//WhoInvitedMe: senderUsername,
		FileKey:    invitation.FileKey,
		InvitedWho: make(map[string]uuid.UUID),
	}
	accessFile_encrypt_key := userlib.RandomBytes(16)
	accessFile.FileKey = userlib.SymEnc(accessFile_encrypt_key, userlib.RandomBytes(16), accessFile.FileKey)

	//Encrypt accessFile.FileKey (File keys)
	accessFile_encrypted_bytes, err := json.Marshal(&accessFile)
	if err != nil {
		return errors.New(strings.ToTitle("Making json error"))
	}

	//Upload the access_file structure (only keys are encrypted)
	accessFile_uuid := invitation.AccessFileUuid
	userlib.DatastoreSet(accessFile_uuid, accessFile_encrypted_bytes)

	//Add AccessFileMap and AccessFileKeyMap
	userdata.AccessFileMap[filename] = accessFile_uuid
	userdata.AccessFileKeyMap[filename] = accessFile_encrypt_key

	UploadUser(userdata)

	return nil
}


func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata = UpdateUser(userdata)

	var i int = 0
	var accessFile_uuid uuid.UUID
	var exist bool
	if i == 0 {
		accessFile_uuid, exist = userdata.MasterFileMap[filename]
	} else {
		accessFile_uuid, exist = userdata.AccessFileMap[filename]
	}

	if !exist { //check if user can access the file
		return errors.New(strings.ToTitle("You don't have authority to revoke this file"))
	}
	accessFile_encrypted_bytes, ok := userlib.DatastoreGet(accessFile_uuid) //get accessFile from Datastore
	if !ok {
		return errors.New(strings.ToTitle("File struct Not Found"))
	}

	var accessFile AccessFile
	err := json.Unmarshal(accessFile_encrypted_bytes, &accessFile)
	if err != nil {
		return errors.New(strings.ToTitle("Unmarshal access file struct error in revoke"))
	}
	accessFile_decrypt_key := userdata.AccessFileKeyMap[filename] //get decrypt key of accessFile struct
	accessFile.FileKey = userlib.SymDec(accessFile_decrypt_key, accessFile.FileKey)

	accessFile_recipient_uuid, found := accessFile.InvitedWho[recipientUsername]
	if !found {
		return errors.New(strings.ToTitle("Recipient already cannot access"))
	}

	delete(accessFile_recipient_uuid, recipientUsername)
	return nil
}

func delete(accfile_uuid uuid.UUID, username string) error {
	accessFile_encrypted_bytes, ok := userlib.DatastoreGet(accfile_uuid) //get accessFile from Datastore
	if !ok {
		return errors.New(strings.ToTitle("File struct Not Found"))
	}
	var accFile AccessFile
	err := json.Unmarshal(accessFile_encrypted_bytes, &accFile)
	if err != nil {
		return errors.New(strings.ToTitle("Unmarshal access file struct error in revoke"))
	}
	for child, uuid := range accFile.InvitedWho {
		delete(uuid, child)
	}
	userlib.DatastoreDelete(accfile_uuid)
	return nil
}
