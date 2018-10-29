pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './gradlew -i'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: 'build/sonatype**.jar')
      }
    }
  }
}