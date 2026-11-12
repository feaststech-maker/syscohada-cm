const express = require('express');

const app = express();

app.get('/', (req, res) => {
  res.send('TBK Builders is running');
});

const port = process.env.PORT || 3000;

app.listen(port, '0.0.0.0', () => {
  console.log(`Server listening on ${port}`);
});
