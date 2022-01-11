const dotenv = require('dotenv');
dotenv.config();
const config = {
    mongoRemote: {
        client: process.env.MONGO_CLIENT,
        cnxStr: process.env.PATH_MONGO,
    }
}
module.exports = config;