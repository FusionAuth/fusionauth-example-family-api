var express = require('express');
var router = express.Router();

const pkceChallenge = require('pkce-challenge').default;
const { FusionAuthClient } = require('@fusionauth/typescript-client');
const clientId = 'a342d269-42dd-4909-a1a9-807601d63750';
const clientSecret = 'HfvqsARHCJfCYj7D7ZqW4guJC1FemcRfHDImcuqX4Es';
const client = new FusionAuthClient('qo7fh-gSYe4CQFfDhUZfbMzzRzRXHDMwBRoG8ItRqFNxQyxu6J1rz9n8', 'http://localhost:9011');
const consentId = '3c3e0176-2f36-4b47-b89b-396f5ffad123';

async function getUserProfiles(familyUsers) {
  const getUsers = familyUsers.map(elem => client.retrieveUser(elem.userId));
  const profiles = await Promise.all(getUsers);
  return profiles;
}

async function getUserConsentStatuses(users) {
  const getUserConsentStatuses = users.map(elem => client.retrieveUserConsents(elem.userId));
  const consentsResponseArray = await Promise.all(getUserConsentStatuses);
  return consentsResponseArray;
}

function buildFamilyArray(users) {
  const family = [];
  users.forEach(user => {
    family.push({ "id": user.response.user.id, "email": user.response.user.email, "role": user.response.user.role });
  });
  return family;
}

function updateFamilyWithConsentStatus(family, consentsResponseArray) {
  const userIdToStatus = {};
  const userIdToUserConsentId = {};
  consentsResponseArray.forEach((consent) => {
    const matchingConsent = consent.response.userConsents.filter((userConsent) => userConsent.consent.id === consentId)[0];
    if (matchingConsent) {
      const userId = matchingConsent.userId;
      userIdToUserConsentId[userId] = matchingConsent.id;
      userIdToStatus[userId] = matchingConsent.status;
    }
  });
  return family.map((member) => {
    member["status"] = userIdToStatus[member.id];
    member["userConsentId"] = userIdToUserConsentId[member.id];
    return member;
  });
}


/* GET home page. */
router.get('/', async function (req, res, next) {
  try {
    let familyProfiles = [];
    const pkce_pair = pkceChallenge();
    req.session.verifier = pkce_pair['code_verifier'];
    req.session.challenge = pkce_pair['code_challenge'];
    if (req.session.user && req.session.user.id) {
      const response = await client.retrieveFamilies(req.session.user.id);
      if (response.response.families && response.response.families.length >= 1) {
        let familyMembers = response.response.families[0].members.filter(elem => elem.role !== 'Adult' || elem.userId === req.session.user.id);
        const userProfiles = await getUserProfiles(familyMembers);
        userProfiles.forEach(user => {
          let self = familyMembers.filter(elem => elem.userId === user.response.user.id)[0];
          user.response.user.role = self.role;
        });
        familyProfiles = buildFamilyArray(userProfiles);
        const consentsResponseArray = await getUserConsentStatuses(familyMembers);
        familyProfiles = updateFamilyWithConsentStatus(familyProfiles, consentsResponseArray);
      }
    }
    res.render('index', {
      family: familyProfiles,
      user: req.session.user,
      title: 'Family Example',
      challenge: pkce_pair['code_challenge']
    });
  } catch (error) {
    console.error("in error");
    console.error(JSON.stringify(error));
    next(error);
  }
});

router.get('/oauth-redirect', async function (req, res, next) {
  try {
    const response = await client.exchangeOAuthCodeForAccessTokenUsingPKCE(
      req.query.code,
      clientId,
      clientSecret,
      'http://localhost:3000/oauth-redirect',
      req.session.verifier
    );

    req.session.state = req.query.state;

    const userResponse = await client.retrieveUserUsingJWT(
      response.response.access_token
    );

    req.session.user = userResponse.response.user;

    res.redirect(302, '/');
  } catch (err) {
    console.log('in error');
    console.error(JSON.stringify(err));
  }
});


/* Change consent */
router.post('/change-consent-status', async function (req, res, next) {
  if (!req.session.user) {
    // force signin
    res.redirect(302, '/');
  }

  let desiredStatus = req.body.desiredStatus;
  if (desiredStatus !== 'Active') {
    desiredStatus = 'Revoked';
  }

  try {
    // check current user is an adult and that the child is part of their family. 
    const response = await client.retrieveFamilies(req.session.user.id);
    if (response.response.families && response.response.families.length >= 1) {
      let self = response.response.families[0].members.filter(elem => elem.userId === req.session.user.id)[0];
      if (self.role !== 'Adult') {
        res.send(403, 'Only Adult users can change consents');
      }
      if (response.response.families[0].members.filter(elem => elem.userId === req.body.userId).length < 1) {
        res.send(403, 'You cannot access families you are not part of');
      }
    }

    // Now get the UserConsent for the child, or create one if not available:

    const consentsResponse = await client.retrieveUserConsents(req.body.userId);
    let userConsent = consentsResponse.response.userConsents.filter((userConsent) => userConsent.consent.id === consentId)[0];
    if (!userConsent) {
      // The child does not yet have a consent. Create a consent for this child.
      const createConsent = await client.createUserConsent(null, {
        userConsent: {
          consentId: consentId,
          giverUserId: req.session.user.id,
          status: "Active",
          userId: req.body.userId
        }
      });
      userConsent = createConsent.response.userConsent;
    }

    const patchBody = { userConsent: { status: desiredStatus } };
    await client.patchUserConsent(userConsent.id, patchBody);

    res.redirect(302, '/');
  } catch (err) {
    console.log('in error');
    console.error(JSON.stringify(err));
    next(err);
  }
});


module.exports = router;
