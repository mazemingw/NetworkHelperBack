const dotenv = require('dotenv');

dotenv.config();

const express = require('express');
const app = express();
const routes = require('./routes');

app.use(express.json({ limit: '128mb' }));
app.use(express.urlencoded({ extended: true, limit: '128mb' }));

app.use('/networkhelp', routes);

const PORT = Number(process.env.PORT || 9895);
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
