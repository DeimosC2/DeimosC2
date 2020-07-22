package gobfuscate

import (
	"bytes"
	"errors"
	"go/build"
	"go/parser"
	"go/token"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"

	"github.com/DeimosC2/DeimosC2/lib/logging"
	"golang.org/x/tools/refactor/rename"
)

//ObfuscatePackageNames obfuscates package names
func ObfuscatePackageNames(gopath string, n NameHasher, ctx build.Context) string {
	// ctx := build.Default
	// ctx.GOPATH = gopath
	logging.Logger.Println("The gopath is:", gopath)

	var ogPKG string
	level := 1
	srcDir := path.Join(gopath, "src")

	doneChan := make(chan struct{})
	defer close(doneChan)

	for {
		resChan := make(chan string)
		go func() {
			scanLevel(srcDir, level, resChan, doneChan)
			close(resChan)
		}()
		var gotAny bool
		for dirPath := range resChan {
			gotAny = true
			if containsCGO(dirPath) { //dies if cgo because it cant fuck with it
				continue
			}
			logging.Logger.Println("dirPath is:", dirPath)
			//ignore everything we fucking can
			if strings.Contains(dirPath, "golang.org") {
				continue
			}
			isMain := isMainPackage(dirPath)          //was it main? we will pass this in ourselves rather than spin cpu cycles
			encPath := EncryptPackageName(dirPath, n) //returned the new hashfile name
			//logging.Logger.Println("EncPath is:", encPath)
			srcPkg, err := filepath.Rel(srcDir, dirPath)
			if err != nil {
				logging.Logger.Println(err)
				return ""
			}
			srcPkg = strings.Replace(srcPkg, string(filepath.Separator), "/", -1)
			logging.Logger.Println("srcPKG is:", srcPkg)
			dstPkg, err := filepath.Rel(srcDir, encPath) //get relative path between where we are (src) and where we wanna be (aka the new enc path)
			if err != nil {
				logging.Logger.Println("filepath.REL error is:", err)
				return ""
			}
			dstPkg = strings.Replace(dstPkg, string(filepath.Separator), "/", -1)
			logging.Logger.Println("dstpackage is:", dstPkg)
			if err := rename.Move(&ctx, srcPkg, dstPkg, ""); err != nil { //moves it and fixes all the other paths that need to be delt with
				logging.Logger.Println("package move:", err)
				return ""
			}
			if isMain {
				ogPKG = encPath
				logging.Logger.Println("main pkg is:", ogPKG)

				if err := makeMainPackage(encPath); err != nil {
					logging.Logger.Println("make main package", encPath, err)
					return ""
				}
			}
		}
		if !gotAny {
			break
		}
		level++
	}

	return ogPKG
}

//looks for files in each dir level
func scanLevel(dir string, depth int, res chan<- string, done <-chan struct{}) {
	if depth == 0 {
		select {
		case res <- dir:
		case <-done:
			return
		}
		return
	}
	listing, _ := ioutil.ReadDir(dir)
	for _, item := range listing {
		if item.IsDir() {
			scanLevel(path.Join(dir, item.Name()), depth-1, res, done)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

//EncryptPackageName Takes the file and gets the filename then makes it a hash of the name and returns the new filepath
func EncryptPackageName(dir string, p NameHasher) string {
	//logging.Logger.Println("encryptpackagenamecalled")
	subDir, base := filepath.Split(dir)
	return path.Join(subDir, p.Hash(base))
}

//simply returns int he package was the main or naw
func isMainPackage(dir string) bool {
	//logging.Logger.Println("ismainpackagecalled")
	listing, err := ioutil.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, item := range listing {
		if isGoFile(item.Name()) {
			path := path.Join(dir, item.Name())
			set := token.NewFileSet()
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return false
			}
			file, err := parser.ParseFile(set, path, contents, 0)
			if err != nil {
				return false
			}
			fields := strings.Fields(string(contents[int(file.Package)-1:]))
			if len(fields) < 2 {
				return false
			}
			return fields[1] == "main"
		}
	}
	return false
}

//does this to make it back to main after they fuck it up
func makeMainPackage(dir string) error {
	//logging.Logger.Println("MakeMainpackage called")
	listing, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, item := range listing {
		if !isGoFile(item.Name()) {
			continue
		}
		path := path.Join(dir, item.Name())
		contents, err := ioutil.ReadFile(path)
		if err != nil {
			logging.Logger.Println(err)
			return err
		}

		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, contents, 0)
		if err != nil {
			logging.Logger.Println(err)
			return err
		}

		pkgNameIdx := int(file.Package) + len("package") - 1
		prePkg := contents[:pkgNameIdx]
		postPkg := string(contents[pkgNameIdx:])

		fields := strings.Fields(postPkg)
		if len(fields) < 1 {
			return errors.New("no fields after package keyword")
		}
		packageName := fields[0]

		var newData bytes.Buffer
		newData.Write(prePkg)
		newData.WriteString(strings.Replace(postPkg, packageName, "main", 1))

		if err := ioutil.WriteFile(path, newData.Bytes(), item.Mode()); err != nil {
			return err
		}
	}
	return nil
}
