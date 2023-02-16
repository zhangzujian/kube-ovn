package main

import (
	"fmt"
	"go/build"

	"github.com/go-git/go-billy/v5/osfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

func main() {
	fmt.Println(build.ToolDir)

	ctx := build.Default
	ctx.GOOS = "windows"
	pkg, err := ctx.ImportDir("./cmd/windows", build.FindOnly)
	// pkg, err := ctx.Import("./cmd/windows", ".", build.FindOnly)
	if err != nil {
		panic(err)
	}

	fmt.Println(pkg.Dir)
	fmt.Println(pkg.Root)
	fmt.Println(pkg.Name)
	fmt.Println(pkg.Imports)
	fmt.Println(pkg.ImportPath)
	return

	dir := "."
	fs := osfs.New(dir)
	dot, _ := fs.Chroot(git.GitDirName)
	storage := filesystem.NewStorage(dot, cache.NewObjectLRUDefault())
	repo, err := git.Open(storage, fs)
	if err != nil {
		panic(err)
	}
	head, err := repo.Head()
	if err != nil {
		panic(err)
	}

	headCommit, err := object.GetCommit(storage, head.Hash())
	if err != nil {
		panic(err)
	}
	parentCommit, err := headCommit.Parents().Next()
	if err != nil {
		panic(err)
	}
	patch, err := headCommit.Patch(parentCommit)
	if err != nil {
		panic(err)
	}
	for _, p := range patch.FilePatches() {
		_, f := p.Files()
		fmt.Println(f.Path())
	}
}
