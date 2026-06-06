# Provii Issuer Demo ProGuard Rules

# Keep Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep API model classes
-keep class app.provii.demo.issuer.api.** { *; }

# Keep Ktor
-keep class io.ktor.** { *; }
-keep class kotlinx.coroutines.** { *; }
