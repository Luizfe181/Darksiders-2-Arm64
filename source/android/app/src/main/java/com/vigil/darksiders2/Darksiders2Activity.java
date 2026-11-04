package com.vigil.darksiders2;

import org.libsdl.app.SDLActivity;

/**
 * SDL2 entry point for the Darksiders II port.
 *
 * SDLActivity loads the libraries below on a worker thread and then calls
 * SDL_main() in the last one -- the entry point our runtime exports. The order
 * matters: SDL2 first, the runtime (which links against it) second.
 */
public class Darksiders2Activity extends SDLActivity {

    @Override
    protected String[] getLibraries() {
        return new String[] {
            "SDL2",
            "darksiders2_runtime"
        };
    }
}
