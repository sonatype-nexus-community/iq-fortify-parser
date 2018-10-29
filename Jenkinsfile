pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './gradlew -i clean assemble'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: 'build/libs/sonatype**.jar')
      }
    }
  }
}