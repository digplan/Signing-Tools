# What is the idea?

SimpleSign https://github.com/digplan/simplesign

SimpleSign is a foundational technology that enables non-technical people, machines, and IOT devices anywhere in the world to easily prove identity, sign and verify any digital file, authenticate without passwords, and send encrypted information.

We are not inventing new cryptography.  Outstanding cryptography already exists.  But, it is too difficult to use for the non-technical person.  We leverage proven cryptographic methods, making them easy to use and implement in all kinds of applications, including web apps, mobile, machine-to-machine, and IOT/Embedded.

With SimpleSign, a person, group, organization, or machine/device may have several 'identities'.  Each identity is as simple as this:

Public:   e3b0c44298fc1c149afbf4c8996fb92427
Private:  cf83e1357eefb8bdf1542850d66d8007d

These identities are easily used, implemented into applications, saved to secure keystores, or invalidated as needed.  They are simply public/private keypairs.

SimpleSign is fully compatible with ANY technology that uses ECDSA public/private key pairs.

For instance, every BITCOIN address in existence can be used by SimpleSign as an identity:
Public: 14Su6eXefCy6gjhufLKnM9FiCnzZF4kggM
Private: 5JreE9kFMpPscrNHuSSrUvtEBN6Vd1ab9GcwhvMXWn9hxPFpko4

SimpleSign identities are very short, so are easily understood and transferred, but an identity has all the power of public/private key cryptography. 

- You can use a private key to authenticate to a web service or application
- You can use a private key to sign a message and have the world validate the signature
- You can use a public key to send encrypted messages that only the recipient can decode
- You can use identities for machine to machine authentication

SimpleSign brings the full power of cryptography: authentication, private communication, digital signing, etc.. in the easiest to use package ever.

# What are the goals

SimpleSign is part of an effort to bring the full power of cryptography to bear to strengthen security, privacy, and authentication, by creating technologies that are easy to use for non-technical people.

A core principle of the effort is to reduce the need for SHARED SECRETS. The widespread sharing of ANY passwords, private keys, and personal information with ANYONE is dangerous.  

What happens when you share any personal token?

- This has resulted in EVERY password leak, since websites/providers are STORING your personal password
- This has caused EVERY Bitcoin and Crypto exchange calamity, when the exchange held everyone's private keys without appropriate security

In short, only a TRUSTLESS system can be reliable. Any sharing of your private secret is unsafe, since no "trusted party" can be guaranteed to be secure.

Public key cryptography has already solved this problem, using the complementary nature of public/private keys, as opposed to sharing secrets.  Very simply, a personal private key is NEVER shared with anyone.  But the public key may be shared with everyone.

Eliminating shared secrets removes a wide-ranging set of internet vulnerabilities, and must be a core focus of all developing security and privacy technologies.

# How will it be done

Funding SimpleSign will bring to the public an OPEN SOURCE standard that will be the easiest to implement and easiest to adopt private/public key proof of identity and encryption ever created.

100% of the funds will be used to fund development to an ALPHA/BETA stage, and bring the project to the public eye to the extent that afterwards, free open-source development effort can be obtained, and further corporate and/or public sponsorship.

We expect 4 months to get to ALPHA, and additional 6 months to get to BETA.

No funding will be used for administrative purposes, for instance, rent, hardware, cloud services, SAAS, etc.. We have all secured the FREE services we need for code hosting, cloud services, collaboration, and continuous integration testing.  Funds can be fully committed to skilled development persons and public awareness.

SimpleSign is a project of Digital Planets, an organization that builds future Internet technologies, and is founded by a 20 year veteran in software development and large corporate implementation.

# Who is this for?

This project is for use by the Internet community as a whole.  Especially the non-technical people in the world, who now make up the vast majority of Internet users.  

These people WILL NOT ADOPT any technologies that bring any friction.  So, they are insecure.  

Consider that Edward Snowden's initial contact to a reporter was REBUFFED because the reporter was not willing to undergo the necessary security measures to ensure confidential communications. Too much work.

Crypto technologies already exist to solve the problems of privacy, security, and identity.  They are too difficult to use, and so will NOT be adopted.  Billions of people use email.  How many people use PGP or encryption mechanisms that do not depend on the security and "goodwill" of their technology providers?

SimpleSign can also be used by product developers of all types, to prove identity for their users and/or any type of device. 

# What community exists?

The project is freely available on GitHub at https://github.com/digplan/simplesign
This project will be promoted and an outreach effort will be made to developers, influencers, and industry contacts once we get closer to ALPHA release.

# Why is this needed?

The existing landscape of privacy, security, and identity on the global Internet is nearly at crisis levels, and getting worse.  That is, if you care at all about ensuring you can prove your identity, authorship of digital files, ability to send encrypted messages, and ability to be anonymous on the Internet.

Make no mistake, anonymity is danger of being completely eliminated over the next decade.

We are at a point where proving identity and authorship of digital files will become a matter of life or death, and global and national security.

For instance, we are very close to the point where fake audio and video can be created that depict anything, and will be impossible to tell from real video.  This is incredibly dangerous without means to "sign" videos that you have created.  A provider, such as YouTube, could be trusted to validate your authorship - and now you have completely lost the right to be anonymous on the Internet - and that right is gone forever.

Every password breach including the high-profile Equifax (143 million users), Yahoo (3 billion users), eBay (145 million users), and many others, have proven that no service provider, no matter how wealthy or well known the company, is exempt from being successfully attacked.  

Now, imagine if user data was always signed and no passwords existed on the servers to be stolen.  Many Bitcoin holds would be much happier (and richer) if they never gave up their private keys to easily hackable exchanges.

SimpleSign distills the power of proven existing cryptography, and puts it in the hands of everyone who needs it.  These technologies must be EASY to adopt and implement.  SimpleSign is a tool to make it possible.

# Similar efforts

The cryptocurrencies are seeking to bring safe and trustless money to the Internet.  Major companies are working on both proprietary and universal standards to address security and privacy issues, but often addressing more specific use cases. Can you sign an email with a Bitcoin key?  With SimpleSign you can.

But, recent history has shown us that universal standards (SAML, XML, etc..) have been complicated and difficult to implement, and technologies that are difficult to implement WILL NOT be widely adopted, or must be revised later to simplify them, because of the cost and difficulty of implementing them.  

Take OAuth for instance.  OAuth version 1 was easy to understand and implement.  The OAuth 2 spec made it more complex.  There is nothing wrong with complexity but only NECESSARY complexity. 
OAuth2 ended many third party Twitter apps.

Where is the ecosystem of security applications based on a SIMPLE standard that is really trustless?  

SimpleSign is unique because it is less-engineered, and easily compatible with other privacy/protection technologies.

