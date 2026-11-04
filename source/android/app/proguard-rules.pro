# Darksiders II - regras ProGuard
#
# O build de debug nao faz minify, por isso estas regras so importam no release.
# SDL e a Activity sao chamadas por JNI: os nomes nao podem ser alterados.

-keep class org.libsdl.app.** { *; }
-keep class com.vigil.darksiders2.** { *; }

# Metodos chamados a partir do codigo nativo.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Vulkan/DXVK carregados por dlopen a partir do runtime.
-keepclassmembers class * {
    *** getLibraries();
}
