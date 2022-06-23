# [WIP] 0xNotes Go Server ![](https://img.shields.io/github/go-mod/go-version/get0xNotes/server) ![](https://img.shields.io/badge/stability-wip-lightgrey)

## ⚠️ Warning ⚠️

Not for production, use the [Python server](https://github.com/get0xNotes/0xNotes/tree/server) instead. This project aims to be 95% compatible with the Python server, using the same API paths.

## What's wrong with the Python server?

As Python is an interpreted language, the server might be a bit slower than server written in compiled languages, like Go. With Go, the server should be able to handle more requests, as well as lowering the CPU and memory utilization. The ability to compile the code into a single executable binary is a big advantage, allowing the server to be deployed on any platform.

## To Do

Implementation:
- [x] `/`
- [x] `/api/v1/user/signup`
- [x] `/api/v1/user/available`
- [x] `/api/v1/user/session`
- [ ] `/api/v1/notes/create`
- [ ] `/api/v1/notes/update/<int:note_id>`
- [x] `/api/v1/notes/list`
- [ ] `/api/v1/notes/<int:note_id>`
- [x] `/api/v1/user/totp`
- [x] `/api/v1/user/totp/enable`
- [ ] `/api/v1/user/totp/disable`

Fix:
- [ ] Scanning `NULL` totp secret from DB.
- [ ] Replace "log.Panic" to print (without calling panic) so that the client can receive an error message.
