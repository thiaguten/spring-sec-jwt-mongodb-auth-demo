// MongoDB Playground
// Use Ctrl+Space inside a snippet or a string literal to trigger completions.

// The current database to use.
use('teste');

let now = ISODate();

// Create a new document in the collection.
db.getCollection('users').insertOne({
    username: "usr-admin",
    // raw password bcrypt encoded
    password: "$2a$10$wV6AuQUqeOE.yMAiR4h.9.Pt6YThXQMjqdM8FtQmn69rYifHdr4o6",
    enabled: true,
    roles: [
        {
            name: "ADMIN",
            description: "Usuário administrativo - interno",
        },
    ],
    createdAt: now,
    modifiedAt: now,
    _class: "br.com.thiaguten.app.user.model.User",
});
