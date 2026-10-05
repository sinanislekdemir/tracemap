package main

import (
	"context"
	"log"
	"os"
	"runtime"

	qt "github.com/mappu/miqt/qt6"

	"traceroute/internal/mapdata"
)

func main() {
	// Qt requires the GUI to live on the process's main thread.
	runtime.LockOSThread()

	qt.NewQApplication(os.Args)
	qt.QGuiApplication_SetApplicationDisplayName("Traceroute Map")

	world, err := mapdata.Load()
	if err != nil {
		log.Printf("mapdata: %v", err)
		world = &mapdata.World{}
	}

	app := NewApp()
	app.startup(context.Background())

	ui := newUI(app, world)
	ui.run()

	app.shutdown(context.Background())
}
