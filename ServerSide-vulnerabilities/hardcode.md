# Main
Hardcode is directly typing at source code.
In some website, there is security incident checking authority in frontend by hard-coding.

# Solution
Check the index, Sources.
And you find the admin URL because the website check the admin authority in frontend layer.

# Cases
It's seen in 東ラブ, that is a matching app.
In 東ラブ, the login ids and passwords were checked in app layer, and users could find them.

# Measures
Manage the login date in database, not do it by hardcoding.
And do not check the authority in client side. Check it in server side.
Because every users, even attackers, can see the client side's source code.
