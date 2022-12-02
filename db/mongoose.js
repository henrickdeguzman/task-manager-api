//Handle connection logic to MongoDB
const mongoose = require('mongoose');

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://127.0.0.1:27017/TaskManager', { useNewUrlParser: true }).then(() => {
    console.log('Connected to MongoDB');
}).catch((e) => {
    console.log('Error while connecting to MongoDB');
    console.log(e);
});

// mongoose.set('useCreateIndex', true);
// mongoose.set('useFindAndModify', false);

module.exports = {
    mongoose
};