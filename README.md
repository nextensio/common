# Common

This code is shared across agent, connector and minion. So its kept in a seperate repository of its own
in gitlab and imported from the other repos. So this one is a "private" repository - ie unlike other
go repos we import from our code which are all publicly accessible, this one is only accessible to 
nextensio members and it needs one additional step to be able to use it

## Using private repo

To be able to import a private repo into your code, do the below.

1. Add the following to /home/<you>/.gitconfig 

[url "git@gitlab.com:"]
    insteadOf = https://gitlab.com/

2. GOLANG SPECIFIC: Add this to your .bashrc and ensure all your shells have this environment variable set before you "go build"

    ```
    export GOPRIVATE="gitlab.com"
    export GO111MODULE="on"
    ```
After this from any directory OUTSIDE YOUR $GOPATH, do a "go get gitlab.com/nextensio/common" and in your 
$GOPATH/pkg/ you can see the module downloaded. You can also download a specific version/branch of the module
by saying go get gitlab.com/nextensio/common@your-branch-name for example, and you can use that version downloaded
(you will see the version number printed by the output of go get) in the go.mod file of your project by specifying
the line "gitlab.com/nextensio/common v0.0.0-20210101210846-22c3b1d85600" for example, to ask for that specific
version of common in your project


3. RUST SPECIFIC: For rust, you "might" have to add this to your environment if cargo build complains that its unable to 
fetch the common repository inspite of all the instructions above

    ```
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    ```
If you want to pull in a latest version of common into your repository using common (like the agent repository),
first edit the Cargo.lock file in your other repository (like agent), and remove any one of the blocks refering
to the common repo (just search for nextensio and common in Cargo.lock) - there might be other blocks referring
to this repo (like blocks referring to nextensio and l3proxy, which is also in this common repo), but just 
removing one of the blocks is good enough. After that do a "cargo clean" and do "cargo build" again and it
will pick up the latest of the common repo again


4. When this repository is used in other projects to make a docker image of that project, the docker build of 
that project might try to do a go get from the Dockerfile - and that command usually runs from within a docker
container that docker launches, so the docker container needs access to gitlab. The recommended way to do that
is to create a read-only key for the common repo, instructions at https://docs.gitlab.com/ee/user/project/deploy_keys
Put that key as ~/.ssh/gitlab_rsa and ~/.ssh/gitlab_rsa.pub, and the docker build process will copy it to the 
container and it will remove it from the container once the build is done, ie the key is **NOT STORED** 
anywhere on the container itself !
