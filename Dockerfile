# Use an official Node.js runtime as a parent image
FROM node:14

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the container
COPY code/package*.json ./

# Install app dependencies
RUN npm install

# Bundle app source
COPY code/ .

# Expose port 3000 for the Express.js app
EXPOSE 3000

# Define the command to run your Express.js application
CMD ["node", "app.js"]
