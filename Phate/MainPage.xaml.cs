using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using Phate.Resources;

namespace Phate
{
    public partial class MainPage : PhoneApplicationPage
    {
        public static List<Phate> _active_connections = new List<Phate>();

        // Constructor
        public MainPage()
        {
            InitializeComponent();

            Phate.Initialize(tbStatusBlock, outputBlock);
        }

        // TODO: This needs to be replicated (adding a scroll viewer and having it auto scroll) for the status block.
        private void outputBlock_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            // TextBlocks only handle about 5000 characters, so if we want to be able to continue to show output
            // we need to 'scroll' it ourselves. Right now, we're 'emulating' a fixed sized scrollback buffer 
            // (i.e. after 5000 chars, you lose the prior data).
            //
            // SizeChanged is called after the text is added to outputBlock

            // TODO: Make this configurable in-app
            int buffer_size = 5000;

            int remainder = outputBlock.Text.Length % buffer_size; // the last chunk of data that'll fit in the window
            int blocks = outputBlock.Text.Length / buffer_size; // the number of blocks we're going to be clearing.

            if (blocks == 0)
            {
                ScrollViewer1.ScrollToVerticalOffset(ScrollViewer1.ExtentHeight - ScrollViewer1.ViewportHeight);
                ScrollViewer1.UpdateLayout();
                return; // there's only one screen of data at the moment, so do nothing)
            }
            
            // truncate to the last full buffer_sized chunk of output
            outputBlock.Text = outputBlock.Text.Substring(remainder + ((blocks - 1) * buffer_size), buffer_size);

            ScrollViewer1.ScrollToVerticalOffset(ScrollViewer1.ExtentHeight - ScrollViewer1.ViewportHeight);
            ScrollViewer1.UpdateLayout();
            return;
        }

    }
}