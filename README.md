# Common

This code is shared across agent, connector and minion. So its kept in a seperate repository of its own
in gitlab and imported from the other repos. So this one is a "private" repository - ie unlike other
go repos we import from our code which are all publicly accessible, this one is only accessible to 
nextensio members and it needs one additional step to be able to use it

## Using private repo

To be able to import a private repo into your code, do the below.

1. Add the following to /home/<you>/.gitconfig 

```
[url "git@gitlab.com:"]
    insteadOf = https://gitlab.com/
```

2. Add this to your .bashrc and ensure all your shells have this environment variable set before you "go build"

```
export GOPRIVATE="gitlab.com"
export GO111MODULE="on"

After this from any directory OUTSIDE YOUR $GOPATH, do a "go get gitlab.com/nextensio/common" and in your 
$GOPATH/pkg/ you can see the module downloaded. You can also download a specific version/branch of the module
by saying go get gitlab.com/nextensio/common@your-branch-name for example, and you can use that version downloaded
(you will see the version number printed by the output of go get) in the go.mod file of your project by specifying
the line "gitlab.com/nextensio/common v0.0.0-20210101210846-22c3b1d85600" for example, to ask for that specific
version of common in your project
```

3. When this repository is used in other projects to make a docker image of that project, the docker build of 
that project might try to do a go get from the Dockerfile - and that command usually runs from within a docker
container that docker launches, so the docker container needs access to gitlab. The recommended way to do that
is to create a read-only key for the common repo, instructions at https://docs.gitlab.com/ee/user/project/deploy_keys
Put that key as ~/.ssh/gitlab_rsa and ~/.ssh/gitlab_rsa.pub, and the docker build process will copy it to the 
container and it will remove it from the container once the build is done, ie the key is **NOT STORED** 
anywhere on the container itself !
