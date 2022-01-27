const got = require('got');
const tunnel = require('tunnel');
const ejs = require("ejs");
const http = require('http');


function logError(context, error){
  var errorCode = (typeof error.code === 'undefined' || error.code === null) ? "" : error.code;
  var errorMessage = (typeof error.message === 'undefined' || error.message === null) ? "" : error.message;
  var errorResponseStatusCode = (typeof error.response === 'undefined' || error.response === null || error.response.statusCode === 'undefined' || error.response.statusCode === null ) ? "" : error.response.statusCode;
  var errorResponseStatusMessage = (typeof error.response === 'undefined' || error.response === null || error.response.statusMessage === 'undefined' || error.response.statusMessage === null ) ? "" : error.response.statusMessage;
  var errorResponseBody = (typeof error.response === 'undefined' || error.response === null || error.response.body === 'undefined' || error.response.body === null ) ? "" : error.response.body;

  console.error(
    "Error occur during  %s : %s - %s - %s - %s - %s", 
    context, errorCode, errorMessage, errorResponseStatusCode, errorResponseStatusMessage,  errorResponseBody);  
}

(async () => {
  var severity = new Map();
  severity.set('MINOR', 0);
  severity.set('MAJOR', 1);
  severity.set('CRITICAL', 2);
  severity.set('BLOCKER', 3);
  var hotspotSeverities = {"HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"};

  const data = {
    //sonar-report --sonarurl="https://sonarcloud.io/akashlanghani" --sonarcomponent="akashlanghani:vidly-api-app"  --release=1.1.0 --project="vidly-api-app" --application="akashlanghani" --sinceleakperiod="false" --allbugs="false"

    date: new Date().toDateString(),
    projectName:"vidly-api-app",
    applicationName: "vidly-api-app",
    releaseName: "1.1.0",
    pullRequest: "pullrequest",
    branch: "master",
    sinceLeakPeriod: 'true',
    previousPeriod: '',
    allBugs:  'true',
    fixMissingRule: 'true',
    noSecurityHotspot: 'false',
    sonarBaseURL: "https://sonarcloud.io",
    sonarOrganization: "akashlanghani",
    sonarcomponent: "akashlanghani_vidly-api-app",
    // use username and password or token for private projects
    username : "sonarusername",
    password : "sonarpassword",
    token : "sonartoken",
    rules: [],
    issues: [],
    hotspotKeys: []
  };

  const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
  data.deltaAnalysis = data.sinceLeakPeriod ? 'Yes' : 'No';
  const sonarBaseURL = data.sonarBaseURL;
  const sonarComponent = data.sonarcomponent;
  const withOrganization = data.sonarOrganization ? `&organization=${data.sonarOrganization}` : '';
  var headers = {};
  // SonarQube Version
  version = "8.0.0.26327";
  
  var proxy = null;
  // the tunnel agent if a forward proxy is required, or remains null
  var agent = null;

  let DEFAULT_ISSUES_FILTER="";
  let DEFAULT_RULES_FILTER="";
  let ISSUE_STATUSES="";
  let HOTSPOT_STATUSES="TO_REVIEW"

  if(data.noSecurityHotspot || version < "7.3"){
    // hotspots don't exist
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  else if (version >= "7.3" && version < "7.8"){
    // hotspots are stored in the /issues endpoint but issue status doesn't include TO_REVIEW,IN_REVIEW yet
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  else if (version >= "7.8" && version < "8.2"){
    // hotspots are stored in the /issues endpoint and issue status includes TO_REVIEW,IN_REVIEW
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED,TO_REVIEW,IN_REVIEW"
  }
  else{
    // version >= 8.2
    // hotspots are in a dedicated endpoint: rules have type SECURITY_HOTSPOT but issues don't
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN"
  }
  

  // filters for getting rules and issues
  let filterRule = DEFAULT_RULES_FILTER;
  let filterIssue = DEFAULT_ISSUES_FILTER;
  let filterHotspots = "";

  if(data.allBugs){
    filterRule = "";
    filterIssue = "";
  }

  if(data.pullRequest){
    filterIssue=filterIssue + "&pullRequest=" + data.pullRequest
    filterHotspots=filterHotspots + "&pullRequest=" + data.pullRequest
  }

  if(data.branch){
    filterIssue=filterIssue + "&branch=" + data.branch
    filterHotspots=filterHotspots + "&branch=" + data.branch
  }

  if(data.fixMissingRule){
    filterRule = "";
  }


  const username = data.sonarusername;
  const password = data.sonarpassword;
  const token = data.sonartoken;
  if (username && password) {
    // Form authentication with username/password
    try {
      const response = await got.post(`${sonarBaseURL}/api/authentication/login`, {
          agent,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `login=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      });
      headers["Cookie"] = response.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ');
    } catch (error) {
        logError("logging in", error);
        return null;
    }
    
  } else if (token) {
    // Basic authentication with user token
    headers["Authorization"] = "Basic " + Buffer.from(token + ":").toString("base64");
  }

  if (data.sinceLeakPeriod) {
    const res = await got(`${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`, {
      agent,
      headers
    });
    const json = JSON.parse(res.body);
  }

  {
    const pageSize = 500;
    let page = 1;
    let nbResults;

  do {
      try {
          const response = await got(`${sonarBaseURL}/api/rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}${withOrganization}`, {
              agent,
              headers
          });
          page++;
          const json = JSON.parse(response.body);
          nbResults = json.rules.length;
          data.rules = data.rules.concat(json.rules.map(rule => ({
          key: rule.key,
          htmlDesc: rule.htmlDesc,
          name: rule.name,
          severity: rule.severity
          })));
      } catch (error) {
          logError("getting rules", error);
          return null;
      }
    } while (nbResults === pageSize);
  }

  {
    const pageSize = 500;
    let page = 1;
    let nbResults;
    do {
      try {
        const response = await got(`${sonarBaseURL}/api/issues/search?componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${ISSUE_STATUSES}&resolutions=&s=STATUS&asc=no${leakPeriodFilter}${filterIssue}`, {
              agent,
              headers
          });
          page++;
          const json = JSON.parse(response.body);
          nbResults = json.issues.length;
          console.log("================== getting issues count: "+nbResults );

          data.issues = data.issues.concat(json.issues.map(issue => {
            const rule = data.rules.find(oneRule => oneRule.key === issue.rule);
            const message = rule ? rule.name : "/";
            console.log("================== getting issues message => " +  issue.message.toString());

            return {
              rule: issue.rule,
              // For security hotspots, the vulnerabilities show without a severity before they are confirmed
              // In this case, get the severity from the rule
              severity: (typeof issue.severity !== 'undefined') ? issue.severity : rule.severity,
              status: issue.status,
              // Take only filename with path, without project name
              component: issue.component.split(':').pop(),
              line: issue.line,
              description: message,
              message: issue.message,
              key: issue.key

            };
          }));

      } catch (error) {
        logError("getting issues", error);  
          return null;
      }
    } while (nbResults === pageSize);

    let hSeverity = "";
    if (version >= "8.2" && !data.noSecurityHotspot) {
      page = 1;
      do {
        try {
            // const response = await got("https://sonarcloud.io/api/issues/search?componentKeys=akashlanghani_vidly-api-app&ps=100", {
            const response = await got(`${sonarBaseURL}/api/hotspots/search?projectKey=${sonarComponent}${filterHotspots}${withOrganization}&ps=${pageSize}&p=${page}&statuses=${HOTSPOT_STATUSES}`, {
                agent,
                headers
            });
            page++;
            
            const json = JSON.parse(response.body);
            nbResults = json.hotspots.length;
            data.hotspotKeys = json.hotspots.map(hotspot => hotspot.key);
        } catch (error) {
          logError("getting hotspots list", error);  
            return null;
        }
      } while (nbResults === pageSize);

      for (let hotspotKey of data.hotspotKeys){
        try {
            const response = await got(`${sonarBaseURL}/api/hotspots/show?hotspot=${hotspotKey}`, {
                agent,
                headers
            });
            const hotspot = JSON.parse(response.body);
            hSeverity = hotspotSeverities[hotspot.rule.vulnerabilityProbability];
            if (hSeverity === undefined) {
              hSeverity = "MAJOR";
              console.error("Unknown hotspot severity: %s", hotspot.vulnerabilityProbability);
            }
            data.issues.push(
              {
                rule: hotspot.rule.key,
                severity: hSeverity,
                status: hotspot.status,
                // Take only filename with path, without project name
                component: hotspot.component.key.split(':').pop(),
                line: hotspot.line,
                description: hotspot.rule ? hotspot.rule.name : "/",
                message: hotspot.message,
                key: hotspot.key
              });
        } catch (error) {
          logError("getting hotspots details", error);  
            return null;
        }
      }
    }


    data.issues.sort(function (a, b) {
      return severity.get(b.severity) - severity.get(a.severity);
    });
  
    data.summary = {
      blocker: data.issues.filter(issue => issue.severity === "BLOCKER").length,
      critical: data.issues.filter(issue => issue.severity === "CRITICAL").length,
      major: data.issues.filter(issue => issue.severity === "MAJOR").length,
      minor: data.issues.filter(issue => issue.severity === "MINOR").length
    };
  }
  
  ejs.renderFile(`${__dirname}/index.ejs`, data, {}, (err, str) => {
    const fs = require('fs');
    fs.writeFileSync('tmp/data.txt', str);
    fs.writeFileSync('tmp/test.html', str);
    console.log("/tmp/test.html file created ");
  });
})();
