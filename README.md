# Family API grant consent 

This project contains an example application that demonstrates how to use the family API to grant access to restricted sections of a web app.

## Prerequisites

You will need the following things properly installed on your computer.

* [Git](http://git-scm.com/): Presumably you already have this on your machine if you are looking at this project locally; if not, use your platform's package manager to install git, and `git clone` this repo.
* [Node.js](https://nodejs.org) and a node package manager like `npm` to install dependencies of the Next.js application and start it up.
* [Docker](https://www.docker.com): For setting up FusionAuth from within a Docker container. (You can [install it other ways](https://fusionauth.io/docs/v1/tech/installation-guide/), but for this example you'll need Docker.)


## Installation and Running

* `git clone https://github.com/ritza-co/fusionauth-family-api-example.git`
* `cd fusionauth-family-api-example`
* `docker-compose up` (this will block the current terminal).

In a new terminal

* `cd app`
* `npm run install`
* `npm start` (this will block the current terminal)

* [Open a browser](http://localhost:3000) to see result and click "Login".
* Parent credentials: ("parent@example.com"/"password")
* Child credentials: ("child@example.com"/"password")

* Log in to the FusionAuth admin interface using ("richard@example.com"/"password")


## FusionAuth Configuration

This example assumes that you will run FusionAuth from a Docker container. In the root of this project directory (next to this README) are two files [a Docker compose file](./docker-compose.yml) and an [environment variables configuration file](./.env). Assuming you have Docker installed on your machine, a `docker-compose up` will bring FusionAuth up on your machine.

The FusionAuth configuration files also make use of a unique feature of FusionAuth, called Kickstart: when FusionAuth comes up for the first time, it will look at the [Kickstart file](./kickstart/kickstart.json) and mimic API calls to configure FusionAuth for use. It will perform all the necessary setup to make this demo work correctly.

For now, get FusionAuth in Docker up and running (via `docker-compose up`) if it is not already running; to see, [click here](http://localhost:9011/) to verify FusionAuth is up and running.

> **NOTE**: If you ever want to reset the FusionAuth system, delete the volumes created by docker-compose by executing `docker-compose down -v`. FusionAuth will only apply the Kickstart settings when it is first run (e.g., it has no data configured for it yet).
