# PA

Github repository: https://github.com/styinx/PA

## Build via command line

Choose path 'closure-compiler':

> mvn -DskipTests -pl externs/pom.xml,pom-main.xml,pom-main-shaded.xml

## Execute via command line

> java -jar closure-compiler-1.0-SNAPSHOT.jar --js='path to the JS file'