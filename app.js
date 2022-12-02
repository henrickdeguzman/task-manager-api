const express = require('express');
const app = express();

const { mongoose } = require('./db/mongoose');

const bodyParser = require('body-parser');

//Load mongoose models
const { List, Task, User } = require('./db/models');

const jwt = require('jsonwebtoken');

//Middleware

let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    //verify jwt
    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if (err) {
            //jwt invalid
            res.status(401).send(err);
        }
        else {
            //jwt valid
            req.user_id = decoded._id;

            next();
        }
    });
}

//Verify refresh token middleware (verify session)
let verifySession = (req, res, next) => {
    let refreshToken = req.header('x-refresh-token');
    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if (!user) {
            return Promise.reject({
                'error': 'User not found.'
            })
        }

        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    isSessionValid = true;
                }
            }
        })

        if (isSessionValid) {
            next();
        }
        else {
            return Promise.reject({
                'error': 'Refresh token has expired.'
            })
        }
    }).catch((e) => {
        res.status(401).send(e);
    })
};

//load middleware
app.use(bodyParser.json());

//Cors
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

    res.header("Access-Control-Expose-Headers", "x-access-token, x-refresh-token, _id");

    next();
});

// Route Handlers

// List Routes
app.get('/lists', authenticate, (req, res) => {
    //Return an array of all the list in the DB
    List.find({
        _userId: req.user_id
    }).then((lists) => {
        res.send(lists);
    });
});
app.post('/lists', authenticate, (req, res) => {
    //Create new list
    let title = req.body.title;

    let newList = new List({
        title,
        _userId: req.user_id
    });
    newList.save().then((listDoc) => {
        //List Doc returned
        res.send(listDoc);
    })
});
app.patch('/lists/:id', authenticate, (req, res) => {
    //Update specified list
    List.findOneAndUpdate({ _id: req.params.id, _userId: req.user_id }, { $set: req.body }).then(() => {
        res.send({ 'message': 'updated successfully' });
    });
});
app.delete('/lists/:id', authenticate, (req, res) => {
    //Delete specified list
    List.findOneAndRemove({ _id: req.params.id, _userId: req.user_id }).then((removeListDoc) => {
        res.send(removeListDoc);

        //delete all task in the list
        deleteTaskFromList(removeListDoc._id);
    });
})

//Task Routes
app.get('/lists/:listId/tasks', authenticate, (req, res) => {
    //Return an array of all the tasks in the DB
    Task.find({
        _listId: req.params.listId
    }).then((tasks) => {
        res.send(tasks);
    });
});
app.post('/lists/:listId/tasks', authenticate, (req, res) => {
    //check
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            //valid
            return true;
        }

        return false;
    }).then((canCreateTask) => {
        if (canCreateTask) {
            //Create new task
            let newTask = new Task({
                title: req.body.title,
                _listId: req.params.listId
            });
            newTask.save().then((taskDoc) => {
                //Task Doc returned
                res.send(taskDoc);
            })
        }
        else {
            res.sendStatus(404);
        }
    });
});
app.patch('/lists/:listId/tasks/:taskId', authenticate, (req, res) => {
    //check
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            //valid
            return true;
        }

        return false;
    }).then((canUpdateTask) => {
        if (canUpdateTask) {
            //Update specified task
            Task.findOneAndUpdate({
                _id: req.params.taskId,
                _listId: req.params.listId
            }, { $set: req.body }).then(() => {
                res.send({ message: "Updated" });
            });
        }
        else {
            res.sendStatus(404);
        }
    });
});
app.delete('/lists/:listId/tasks/:taskId', authenticate, (req, res) => {
    //check
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            //valid
            return true;
        }

        return false;
    }).then((canDeleteTask) => {
        if (canDeleteTask) {
            //Delete specified task
            Task.findOneAndRemove({
                _id: req.params.taskId,
                _listId: req.params.listId
            }).then((removeTaskDoc) => {
                res.send(removeTaskDoc);
            });
        }
        else {
            res.sendStatus(404);
        }
    });
})

app.post('/users', (req, res) => {
    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        return newUser.generateAccessAuthToken().then((accessToken) => {
            return { accessToken, refreshToken }
        })
    }).then((authTokens) => {
        res.header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
    }).catch((e) => {
        console.log(e);
        res.status(400).send(e);
    })
})

app.post('/users/login', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            return user.generateAccessAuthToken().then((accessToken) => {
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
            res.header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})

app.get('/users/me/access-token', verifySession, (req, res) => {
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({ accessToken });
    }).catch((e) => {
        res.status(400).send(e);
    });
});

//Helper method
let deleteTaskFromList = (_listId) => {
    Task.deleteMany({
        _listId
    }).then(() => {
        console.log('task from ' + _listId + ' was deleted')
    })
}

app.listen(3000, () => {
    console.log('server is listening to port 3000');
});