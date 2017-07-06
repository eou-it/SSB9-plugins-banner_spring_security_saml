/*******************************************************************************
 Copyright 2017 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
target(main: "Creates a report of all TODOs") {


    def output = new File( "target/todos-report.html" )
    def fileCount = 0

    def jiraMap = [:]
    def addJiras = { todo ->
        def matcher = todo =~ /(.*?)(HRU-[0-9]+[0-9]+[0-9]+[0-9]+)(.*?)/

        def match = matcher.matches()
        def i = 0
        while (match) {
            def jira = matcher[i][2]

            if (jiraMap[jira]) {
                jiraMap[jira] = jiraMap[jira] + 1
            }
            else {
                jiraMap[jira] = 1
            }
            i++
            match = matcher.find()
        }
    }


    // lets create a scanner of filesets
    def scanner = ant.fileScanner {
        fileset(dir:"${basedir}") {
            include(name:"grails-app/**/*.groovy")
            include(name:"test/**/*.groovy")
            include(name:"src/groovy/**/*.groovy")
            include(name:"src/java/**/*.java")
        }
    }


    // TODO Table
    def todoCount = 0
    def todoBody = ""
    for (f in scanner) {
        if (f.text.contains( "TODO" )) {
            def lineNumber = 0
            f.eachLine { line ->
                lineNumber++
                if (line.contains( "TODO" )) {
                    todoCount++

                    def todo = line.expand().stripIndent()
                    addJiras( todo )

                    def todoUpdated = todo.replaceAll(/(HRU-[0-9]+[0-9]+[0-9]+[0-9]+)/, '<a href="https://jirateams.ellucian.com/browse/$1" target="_blank">$1</a>')
                    todoBody += "<tr><td>${f.absolutePath.minus( basedir + "/" )}</td><td align=\"right\">$lineNumber</td><td>${todoUpdated}</td></tr>"
                }
            }

            fileCount++
        }
    }

    // JIRA Count Table
    def jiraBody = ""
    def jiraCount = 0
    jiraMap.each { jiraCount += it.value }
    def sortedJiraMap = jiraMap.sort { a, b ->
        if (a.value > b.value) {
            return -1
        }
        else if (a.value < b.value) {
            return 1
        }
        else {
            return 0
        }
    }

    sortedJiraMap.each {
        jiraBody += "<tr><td><a href=\"https://jirateams.ellucian.com/browse/${it.key}\" target=\"_blank\">${it.key}</a></td><td align=\"right\">${it.value}</td></tr>"
    }

    output.write """
	    <html>
	        <body>
	            <head>
	                <title>TODOs Report</title>
	                <style type="text/css">
	                    table.report {
	                        border-width: 1px;
	                        border-spacing: 1px;
	                        border-style: outset;
	                        border-color: gray;
	                        border-collapse: separate;
	                        background-color: white;
	                    }
	                    table.report th {
	                        border-width: 1px;
	                        padding: 2px;
	                        border-style: inset;
	                        border-color: gray;
	                        background-color: lightblue;
	                        -moz-border-radius: 0px 0px 0px 0px;
	                        white-space: nowrap;
	                    }
	                    table.report td {
	                        border-width: 1px;
	                        padding: 2px;
	                        border-style: inset;
	                        border-color: gray;
	                        background-color: white;
	                        -moz-border-radius: 0px 0px 0px 0px;
	                    }
	                </style>
	            </head>
	            <h2>TODOs Report</h2>
	            Generated: ${new Date()}
	            <table class="report">
	                <thead>
	                    <th>Path</th>
	                    <th>Line #</th>
	                    <th>Comment</th>
	                </thead>
	                <tfoot>
	                    <tr>
	                        <td colspan="3">Total: ${todoCount} TODOs</td>
	                    </tr>
	                </tfoot>
	                <tbody>
	                    ${todoBody}
	                </tbody>
	            </table>
	            <h2>JIRA Counts</h2>
	            <table class="report">
	                <thead>
	                    <th>JIRA</th>
	                    <th>Count</th>
	                </thead>
	                <tfoot>
	                    <tr>
	                      <td>Total:</td>
	                      <td align=\"right\">${jiraCount}</td>
	                    </tr>
	                </tfoot>
	                <tbody>
	                    ${jiraBody}
	                </tbody>
	            <table>
	        </body>
	    </html>"""

    println "TODO Report ${output} created."
}


setDefaultTarget "main"